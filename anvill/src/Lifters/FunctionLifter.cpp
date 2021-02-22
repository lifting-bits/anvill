/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "FunctionLifter.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <anvill/Decl.h>
#include <anvill/Lifters/DeclLifter.h>
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>
#include <anvill/TypePrinter.h>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>

#include <sstream>

#include "Context.h"

// TODO(pag): Externalize this into some kind of `LifterOptions` struct.
DEFINE_bool(print_registers_before_instuctions, false,
            "Inject calls to printf (into the lifted bitcode) to log integer "
            "register state to stdout.");

namespace anvill {
namespace {

// Clear out LLVM variable names. They're usually not helpful.
static void ClearVariableNames(llvm::Function *func) {
  for (auto &block : *func) {
    block.setName(llvm::Twine::createNull());
    for (auto &inst : block) {
      if (inst.hasName()) {
        inst.setName(llvm::Twine::createNull());
      }
    }
  }
}

// Compatibility function for performing a single step of inlining.
static llvm::InlineResult InlineFunction(llvm::CallBase *call,
                                         llvm::InlineFunctionInfo &info) {
#if LLVM_VERSION_NUMBER < LLVM_VERSION(11, 0)
  return llvm::InlineFunction(call, info);
#else
  return llvm::InlineFunction(*call, info);
#endif
}

// A function that ensures that the memory pointer escapes, and thus none of
// the memory writes at the end of a function are lost.
static llvm::Function *
GetMemoryEscapeFunc(const remill::IntrinsicTable &intrinsics) {
  const auto module = intrinsics.error->getParent();
  auto &context = module->getContext();

  const auto name = "__anvill_memory_escape";
  if (auto func = module->getFunction(name)) {
    return func;
  }

  llvm::Type *params[] = {
      remill::NthArgument(intrinsics.error, remill::kMemoryPointerArgNum)
          ->getType()};
  auto type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), params, false);
  return llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, name,
                                module);
}

}  // namespace

FunctionLifterImpl::~FunctionLifterImpl(void) {}

FunctionLifterImpl::FunctionLifterImpl(
    const LifterOptions &options_, MemoryProvider &memory_provider_,
    TypeProvider &type_provider_)
    : options(options_),
      memory_provider(memory_provider_),
      type_provider(type_provider_),
      semantics_module(remill::LoadArchSemantics(options.arch)),
      context(semantics_module->getContext()),
      intrinsics(semantics_module.get()),
      inst_lifter(options.arch, intrinsics),
      is_sparc(options.arch->IsSPARC32() || options.arch->IsSPARC64()),
      i8_type(llvm::Type::getInt8Ty(context)),
      i8_zero(llvm::Constant::getNullValue(i8_type)),
      i32_type(llvm::Type::getInt32Ty(context)),
      mem_ptr_type(llvm::dyn_cast<llvm::PointerType>(
          remill::RecontextualizeType(options.arch->MemoryPointerType(),
                                      context))),
      state_ptr_type(llvm::dyn_cast<llvm::PointerType>(
          remill::RecontextualizeType(options.arch->StatePointerType(),
                                      context))) {}

// Helper to get the basic block to contain the instruction at `addr`. This
// function drives a work list, where the first time we ask for the
// instruction at `addr`, we enqueue a bit of work to decode and lift that
// instruction.
llvm::BasicBlock *FunctionLifterImpl::GetOrCreateBlock(uint64_t addr) {
  const auto from_pc = curr_inst ? curr_inst->pc : 0;
  auto &block = edge_to_dest_block[{from_pc, addr}];
  if (block) {
    return block;
  }

  std::stringstream ss;
  ss << "inst_" << std::hex << addr;
  block = llvm::BasicBlock::Create(context, ss.str(), lifted_func);

  // Missed an instruction?! This can happen when IDA merges two instructions
  // into one larger synthetic instruction. This might also be a tail-call.
  edge_work_list.emplace(addr, from_pc);

  return block;
}

// Try to decode an instruction at address `addr` into `*inst_out`. Returns
// `true` is successful and `false` otherwise. `is_delayed` tells the decoder
// whether or not the instruction being decoded is being decoded inside of a
// delay slot of another instruction.
bool FunctionLifterImpl::DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                                           remill::Instruction *inst_out) {
  static const auto max_inst_size = options.arch->MaxInstructionSize();
  inst_out->Reset();

  // Read the maximum number of bytes possible for instructions on this
  // architecture. For x86(-64), this is 15 bytes, whereas for fixed-width
  // architectures like AArch32/AArch64 and SPARC32/SPARC64, this is 4 bytes.
  inst_out->bytes.reserve(max_inst_size);
  for (auto i = 0u; i < max_inst_size; ++i) {
    auto [byte, accessible, perms] = memory_provider.Query(addr + i);
    switch (accessible) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kUnavailable:
        goto found_all_bytes;

      default:
        break;
    }

    switch (perms) {
      case BytePermission::kUnknown:
      case BytePermission::kReadableExecutable:
      case BytePermission::kReadableWritableExecutable:
        inst_out->bytes.push_back(static_cast<char>(byte));
        break;
      case BytePermission::kReadable:
      case BytePermission::kReadableWritable:
        goto found_all_bytes;
    }
  }

found_all_bytes:

  if (is_delayed) {
    return options.arch->DecodeDelayedInstruction(
        addr, inst_out->bytes, *inst_out);
  } else {
    return options.arch->DecodeInstruction(
        addr, inst_out->bytes, *inst_out);
  }
}

// Visit an invalid instruction. An invalid instruction is a sequence of
// bytes which cannot be decoded, or an empty byte sequence.
void FunctionLifterImpl::VisitInvalid(const remill::Instruction &inst,
                                llvm::BasicBlock *block) {
  remill::AddTerminatingTailCall(block, intrinsics.error);
}

// Visit an error instruction. An error instruction is guaranteed to trap
// execution somehow, e.g. `ud2` on x86. Error instructions are treated
// similarly to invalid instructions, with the exception that they can have
// delay slots, and therefore the subsequent instruction may actually execute
// prior to the error.
void FunctionLifterImpl::VisitError(const remill::Instruction &inst,
                              remill::Instruction *delayed_inst,
                              llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.error);
}

// Visit a normal instruction. Normal instructions have straight line control-
// flow semantics, i.e. after executing the instruction, execution proceeds
// to the next instruction (`inst.next_pc`).
void FunctionLifterImpl::VisitNormal(const remill::Instruction &inst,
                               llvm::BasicBlock *block) {
  llvm::BranchInst::Create(GetOrCreateBlock(inst.next_pc), block);
}

// Visit a no-op instruction. These behave identically to normal instructions
// from a control-flow perspective.
void FunctionLifterImpl::VisitNoOp(const remill::Instruction &inst,
                             llvm::BasicBlock *block) {
  VisitNormal(inst, block);
}

// Visit a direct jump control-flow instruction. The target of the jump is
// known at decode time, and the target address is available in
// `inst.branch_taken_pc`. Execution thus needs to transfer to the instruction
// (and thus `llvm::BasicBlock`) associated with `inst.branch_taken_pc`.
void FunctionLifterImpl::VisitDirectJump(const remill::Instruction &inst,
                                   remill::Instruction *delayed_inst,
                                   llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc), block);
}

// Visit an indirect jump control-flow instruction. This may be register- or
// memory-indirect, e.g. `jmp rax` or `jmp [rax]` on x86. Thus, the target is
// not know a priori and our default mechanism for handling this is to perform
// a tail-call to the `__remill_jump` function, whose role is to be a stand-in
// something that enacts the effect of "transfer to target."
void FunctionLifterImpl::VisitIndirectJump(const remill::Instruction &inst,
                                     remill::Instruction *delayed_inst,
                                     llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.jump);
}

// Visit a function return control-flow instruction, which is a form of
// indirect control-flow, but with a certain semantic associated with
// returning from a function. This is treated similarly to indirect jumps,
// except the `__remill_function_return` function is tail-called.
void FunctionLifterImpl::VisitFunctionReturn(const remill::Instruction &inst,
                                       remill::Instruction *delayed_inst,
                                       llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  llvm::ReturnInst::Create(context, remill::LoadMemoryPointer(block), block);
}

// Visit a direct function call control-flow instruction. The target is known
// at decode time, and its realized address is stored in
// `inst.branch_taken_pc`. In practice, what we do in this situation is try
// to call the lifted function function at the target address.
void FunctionLifterImpl::VisitDirectFunctionCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);

  // First, try to see if it's actually related to another function. This is
  // equivalent to a tail-call in the original code.
  const auto maybe_other_decl =
      type_provider.TryGetFunctionType(inst.branch_taken_pc);

  if (maybe_other_decl) {
    if (const auto other_decl = DeclareFunction(*maybe_other_decl)) {
      const auto mem_ptr_from_call = TryCallNativeFunction(
          inst.branch_taken_pc, other_decl, block);

      if (!mem_ptr_from_call) {
        LOG(ERROR)
            << "Failed to call native function at address " << std::hex
            << inst.branch_taken_pc << " via call at address " << inst.pc
            << " in function at address " << func_address << std::dec;

        // If we fail to create an ABI specification for this function then
        // treat this as a call to an unknown address.
        remill::AddCall(block, intrinsics.function_call);
      }
    } else {
      LOG(ERROR)
          << "Failed to call non-executable memory or invalid address "
          << std::hex << inst.branch_taken_pc << " via call at address "
          << inst.pc << " in function at address " << func_address << std::dec;

      // TODO(pag): Make call `intrinsics.error`?
      remill::AddCall(block, intrinsics.function_call);
    }
  } else {
    LOG(ERROR)
        << "Missing type information for function at address " << std::hex
        << inst.branch_taken_pc << ", called at address "
        << inst.pc << " in function at address " << func_address << std::dec;

    // If we do not have a function declaration, treat this as a call
    // to an unknown address.
    remill::AddCall(block, intrinsics.function_call);
  }

  VisitAfterFunctionCall(inst, block);
}

// Visit an indirect function call control-flow instruction. Similar to
// indirect jumps, we invoke an intrinsic function, `__remill_function_call`;
// however, unlike indirect jumps, we do not tail-call this intrinsic, and
// we continue lifting at the instruction where execution will resume after
// the callee returns. Thus, lifted bitcode maintains the call graph structure
// as it presents itself in the binary.
void FunctionLifterImpl::VisitIndirectFunctionCall(const remill::Instruction &inst,
                                             remill::Instruction *delayed_inst,
                                             llvm::BasicBlock *block) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddCall(block, intrinsics.function_call);
  VisitAfterFunctionCall(inst, block);
}

// Helper to figure out the address where execution will resume after a
// function call. In practice this is the instruction following the function
// call, encoded in `inst.branch_not_taken_pc`. However, SPARC has a terrible
// ABI where they inject an invalid instruction following some calls as a way
// of communicating to the callee that they should return an object of a
// particular, hard-coded size. Thus, we want to actually identify then ignore
// that instruction, and present the following address for where execution
// should resume after a `call`.
std::pair<uint64_t, llvm::Value *>
FunctionLifterImpl::LoadFunctionReturnAddress(const remill::Instruction &inst,
                                        llvm::BasicBlock *block) {

  const auto pc = inst.branch_not_taken_pc;

  // The semantics for handling a call save the expected return program counter
  // into a local variable.
  auto ret_pc =
      inst_lifter.LoadRegValue(block, state_ptr, remill::kReturnPCVariableName);
  if (!is_sparc) {
    return {pc, ret_pc};
  }

  uint8_t bytes[4] = {};

  for (auto i = 0u; i < 4u; ++i) {
    auto [byte, accessible, perms] = memory_provider.Query(pc + i);
    switch (accessible) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kUnavailable:
        LOG(ERROR)
            << "Byte at address " << std::hex << (pc + i)
            << " is not available for inspection to figure out return address "
            << " of call instruction at address " << pc << std::dec;
        return {pc, ret_pc};

      default:
        bytes[i] = byte;
        break;
    }

    switch (perms) {
      case BytePermission::kUnknown:
      case BytePermission::kReadableExecutable:
      case BytePermission::kReadableWritableExecutable:
        break;
      case BytePermission::kReadable:
      case BytePermission::kReadableWritable:
        LOG(ERROR)
            << "Byte at address " << std::hex << (pc + i) << " being inspected "
            << "to figure out return address of call instruction at address "
            << pc << " is not executable" << std::dec;
        return {pc, ret_pc};
    }
  }

  union Format0a {
    uint32_t flat;
    struct {
      uint32_t imm22 : 22;
      uint32_t op2 : 3;
      uint32_t rd : 5;
      uint32_t op : 2;
    } u __attribute__((packed));
  } __attribute__((packed)) enc = {};
  static_assert(sizeof(Format0a) == 4, " ");

  enc.flat |= bytes[0];
  enc.flat <<= 8;
  enc.flat |= bytes[1];
  enc.flat <<= 8;
  enc.flat |= bytes[2];
  enc.flat <<= 8;
  enc.flat |= bytes[3];

  // This looks like an `unimp <imm22>` instruction, where the `imm22` encodes
  // the size of the value to return. See "Programming Note" in v8 manual, B.31,
  // p 137.
  //
  // TODO(pag, kumarak): Does a zero value in `enc.u.imm22` imply a no-return
  //                     function? Try this on Compiler Explorer!
  if (!enc.u.op && !enc.u.op2) {
    LOG(INFO) << "Found structure return of size " << enc.u.imm22 << " to "
              << std::hex << pc << " at " << inst.pc << std::dec;

    llvm::IRBuilder<> ir(block);
    return {pc + 4u,
            ir.CreateAdd(ret_pc, llvm::ConstantInt::get(ret_pc->getType(), 4))};

  } else {
    return {pc, ret_pc};
  }
}

// Enact relevant control-flow changed after a function call. This figures
// out the return address targeted by the callee and links it into the
// control-flow graph.
void FunctionLifterImpl::VisitAfterFunctionCall(const remill::Instruction &inst,
                                          llvm::BasicBlock *block) {
  const auto [ret_pc, ret_pc_val] = LoadFunctionReturnAddress(inst, block);
  const auto next_pc_ptr =
      inst_lifter.LoadRegAddress(block, state_ptr, remill::kNextPCVariableName);

  llvm::IRBuilder<> ir(block);
  ir.CreateStore(ret_pc_val, next_pc_ptr, false);
  ir.CreateBr(GetOrCreateBlock(ret_pc));
}

// Visit a conditional control-flow branch. Both the taken and not taken
// targets are known by the decoder and their addresses are available in
// `inst.branch_taken_pc` and `inst.branch_not_taken_pc`, respectively.
// Here we need to orchestrate the two-way control-flow, as well as the
// possible execution of a delayed instruction on either or both paths,
// depending on the presence/absence of delay slot annulment bits.
void FunctionLifterImpl::VisitConditionalBranch(const remill::Instruction &inst,
                                          remill::Instruction *delayed_inst,
                                          llvm::BasicBlock *block) {

  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block = llvm::BasicBlock::Create(context, "", lifted_func);
  const auto not_taken_block = llvm::BasicBlock::Create(context, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc), taken_block);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

// Visit an asynchronous hyper call control-flow instruction. These are non-
// local control-flow transfers, such as system calls. We treat them like
// indirect function calls.
void FunctionLifterImpl::VisitAsyncHyperCall(const remill::Instruction &inst,
                                       remill::Instruction *delayed_inst,
                                       llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.async_hyper_call);
}

// Visit conditional asynchronous hyper calls. These are conditional, non-
// local control-flow transfers, e.g. `bound` on x86.
void FunctionLifterImpl::VisitConditionalAsyncHyperCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {
  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block = llvm::BasicBlock::Create(context, "", lifted_func);
  const auto not_taken_block = llvm::BasicBlock::Create(context, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);

  remill::AddTerminatingTailCall(taken_block, intrinsics.async_hyper_call);

  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

// Visit (and thus lift) a delayed instruction. When lifting a delayed
// instruction, we need to know if we're one the taken path of a control-flow
// edge, or on the not-taken path. Delayed instructions appear physically
// after some instructions, but execute logically before them in the
// CPU pipeline. They are basically a way for hardware designers to push
// the effort of keeping the pipeline full to compiler developers.
void FunctionLifterImpl::VisitDelayedInstruction(const remill::Instruction &inst,
                                             remill::Instruction *delayed_inst,
                                             llvm::BasicBlock *block,
                                             bool on_taken_path) {
  if (delayed_inst &&
      options.arch->NextInstructionIsDelayed(inst, *delayed_inst,
                                             on_taken_path)) {
    inst_lifter.LiftIntoBlock(*delayed_inst, block, state_ptr, true);
  }
}

// Creates a type hint taint value that we can hook into downstream in the
// optimization process.
//
// This function encodes type information within symbolic functions so the type
// information can survive optimization. It should turn some instruction like
//    %1 = add %4, 1
//
// into:
//
//    %1 = add %4, 1
//    %2 = __anvill_type_<uid>(<%4's type> %4)
//    %3 = ptrtoint %2 goal_type
llvm::Function *FunctionLifterImpl::GetOrCreateTaintedFunction(
    llvm::Type *current_type, llvm::Type *goal_type,
    llvm::BasicBlock *curr_block, const remill::Register *reg,
    uint64_t pc) {

  std::stringstream func_name;
  func_name << "__anvill_type_func_" << std::hex << pc << "_" << reg->name
            << "_" << reinterpret_cast<void *>(current_type);
  llvm::Type *return_type = goal_type;

  auto anvill_type_fn_ty =
      llvm::FunctionType::get(return_type, {current_type}, false);
  semantics_module->getOrInsertFunction(func_name.str(), anvill_type_fn_ty);
  return semantics_module->getFunction(func_name.str());
}

// Instrument an instruction. This inject a `printf` call just before a
// lifted instruction to aid in debugging.
//
// TODO(pag): In future, this mechanism should be used to provide a feedback
//            loop, or to provide information to the `TypeProvider` for future
//            re-lifting of code.
//
// TODO(pag): Right now, this feature is enabled by a command-line flag, and
//            that flag is tested in `VisitInstruction`; we should move
//            lifting configuration decisions out of here so that we can pass
//            in a kind of `LiftingOptions` type that changes the lifter's
//            behavior.
void FunctionLifterImpl::InstrumentInstruction(llvm::BasicBlock *block) {
  if (!log_printf) {
    llvm::Type *args[] = {llvm::Type::getInt8PtrTy(context, 0)};
    auto fty =
        llvm::FunctionType::get(llvm::Type::getVoidTy(context), args, true);

    log_printf = llvm::dyn_cast<llvm::Function>(
        semantics_module->getOrInsertFunction("printf", fty).getCallee());

    std::stringstream ss;
    options.arch->ForEachRegister([&](const remill::Register *reg) {
      if (reg->EnclosingRegister() == reg &&
          reg->type->isIntegerTy(options.arch->address_size)) {
        ss << reg->name << "=%llx ";
      }
    });
    ss << '\n';
    const auto format_str =
        llvm::ConstantDataArray::getString(context, ss.str(), true);
    const auto format_var = new llvm::GlobalVariable(
        *semantics_module, format_str->getType(), true,
        llvm::GlobalValue::InternalLinkage, format_str);

    llvm::Constant *indices[] = {llvm::ConstantInt::getNullValue(i32_type),
                                 llvm::ConstantInt::getNullValue(i32_type)};
    log_format_str = llvm::ConstantExpr::getInBoundsGetElementPtr(
        format_str->getType(), format_var, indices);
  }

  std::vector<llvm::Value *> args;
  args.push_back(log_format_str);
  options.arch->ForEachRegister([&](const remill::Register *reg) {
    if (reg->EnclosingRegister() == reg &&
        reg->type->isIntegerTy(options.arch->address_size)) {
      args.push_back(inst_lifter.LoadRegValue(block, state_ptr, reg->name));
    }
  });

  llvm::IRBuilder<> ir(block);
  ir.CreateCall(log_printf, args);
}

// Visit a type hinted register at the current instruction. We use this
// information to try to improve lifting of possible pointers later on
// in the optimization process.
void FunctionLifterImpl::VisitTypedHintedRegister(
    llvm::BasicBlock *block, const std::string &reg_name, llvm::Type *type,
    std::optional<uint64_t> maybe_value) {

  // Only operate on pointer-sized integer registers that are not sub-registers.
  const auto reg = options.arch->RegisterByName(reg_name);
  if (reg->EnclosingRegister() != reg ||
      !reg->type->isIntegerTy(options.arch->address_size)) {
    return;
  }

  llvm::IRBuilder irb(block);
  auto reg_pointer = inst_lifter.LoadRegAddress(block, state_ptr, reg_name);
  llvm::Value *reg_value = nullptr;

  // If we have a concrete value that is being provided for this value, then
  // save it into the `State` structure. This improves our ability to optimize.
  if (options.store_inferred_register_values && maybe_value) {
    reg_value = irb.CreateLoad(reg_pointer);
    reg_value = llvm::ConstantInt::get(reg->type, *maybe_value);
    irb.CreateStore(reg_value, reg_pointer);
  }

  if (!type->isPointerTy()) {
    return;
  }

  if (!reg_value) {
    reg_value = irb.CreateLoad(reg_pointer);
  }

  // Creates a function that returns a higher-level type, as provided by a
  // `TypeProider`and takes an argument of (reg_type)
  const auto taint_func = GetOrCreateTaintedFunction(
      reg->type, type, block, reg, curr_inst->pc);
  llvm::Value *tainted_call = irb.CreateCall(taint_func, reg_value);

  // Cast the result of this call to the goal type.
  llvm::Value *replacement_reg = irb.CreatePtrToInt(tainted_call, reg->type);

  // Store the value back, this keeps the replacement_reg cast around.
  irb.CreateStore(replacement_reg, reg_pointer);
}

// Visit an instruction, and lift it into a basic block. Then, based off of
// the category of the instruction, invoke one of the category-specific
// lifters to enact a change in control-flow.
void FunctionLifterImpl::VisitInstruction(
    remill::Instruction &inst, llvm::BasicBlock *block) {
  curr_inst = &inst;

  // TODO(pag): Externalize the dependency on this flag to a `LifterOptions`
  //            structure.
  if (FLAGS_print_registers_before_instuctions) {
    InstrumentInstruction(block);
  }

  // Reserve space for an instrucion that will go into a delay slot, in case it
  // is needed. This is an uncommon case, so avoid instantiating a new
  // Instruction unless it is actually needed. The instruction instantition into
  // this buffer happens via a placement new call later on.
  std::aligned_storage<sizeof(remill::Instruction),
                       alignof(remill::Instruction)>::type delayed_inst_storage;

  remill::Instruction *delayed_inst = nullptr;

  // Even when something isn't supported or is invalid, we still lift
  // a call to a semantic, e.g.`INVALID_INSTRUCTION`, so we really want
  // to treat instruction lifting as an operation that can't fail.
  (void) inst_lifter.LiftIntoBlock(inst, block, state_ptr,
                                   false /* is_delayed */);

  // Figure out if we have to decode the subsequent instruction as a delayed
  // instruction.
  if (options.arch->MayHaveDelaySlot(inst)) {
    delayed_inst = new (&delayed_inst_storage) remill::Instruction;
    if (!DecodeInstructionInto(inst.delayed_pc, true /* is_delayed */,
                               delayed_inst)) {
      LOG(ERROR) << "Unable to decode or use delayed instruction at "
                 << std::hex << inst.delayed_pc << std::dec << " of "
                 << inst.Serialize();
    }
  }

  // Try to find any register type hints that we can use later to improve
  // pointer lifting.
  if (options.symbolic_register_types) {
    type_provider.QueryRegisterStateAtInstruction(
        func_address, inst.pc,
        [=] (const std::string &reg_name, llvm::Type *type,
             std::optional<uint64_t> maybe_value) {
          VisitTypedHintedRegister(block, reg_name, type, maybe_value);
        });
  }

  switch (inst.category) {

    // Invalid means failed to decode.
    case remill::Instruction::kCategoryInvalid:
      VisitInvalid(inst, block);
      break;

    // Error is a valid instruction, but specifies error semantics for the
    // processor. The canonical example is x86's `UD2` instruction.
    case remill::Instruction::kCategoryError:
      VisitError(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryNormal: VisitNormal(inst, block); break;
    case remill::Instruction::kCategoryNoOp: VisitNoOp(inst, block); break;
    case remill::Instruction::kCategoryDirectJump:
      VisitDirectJump(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryIndirectJump:
      VisitIndirectJump(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryFunctionReturn:
      VisitFunctionReturn(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryDirectFunctionCall:
      VisitDirectFunctionCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryIndirectFunctionCall:
      VisitIndirectFunctionCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalBranch:
      VisitConditionalBranch(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryAsyncHyperCall:
      VisitAsyncHyperCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      VisitConditionalAsyncHyperCall(inst, delayed_inst, block);
      break;
  }

  if (delayed_inst) {
    delayed_inst->~Instruction();
  }
}

// In the process of lifting code, we may want to call another native
// function, `native_func`, for which we have high-level type info. The main
// lifter operates on a special three-argument form function style, and
// operating on this style is actually to our benefit, as it means that as
// long as we can put data into the emulated `State` structure and pull it
// out, then calling one native function from another doesn't require /us/
// to know how to adapt one native return type into another native return
// type, and instead we let LLVM's optimizations figure it out later during
// scalar replacement of aggregates (SROA).
llvm::Value *FunctionLifterImpl::TryCallNativeFunction(
    uint64_t native_addr, llvm::Function *native_func,
    llvm::BasicBlock *block) {
  auto &decl = addr_to_decl[native_addr];
  if (!decl.address) {
    auto maybe_decl = FunctionDecl::Create(*native_func, options.arch);
    if (remill::IsError(maybe_decl)) {
      LOG(ERROR)
          << "Unable to create FunctionDecl for "
          << remill::LLVMThingToString(native_func->getFunctionType())
          << " with calling convention " << native_func->getCallingConv()
          << ": " << remill::GetErrorString(maybe_decl);
      return nullptr;
    }
    decl = std::move(remill::GetReference(maybe_decl));
  }

  auto mem_ptr_ref = remill::LoadMemoryPointerRef(block);
  llvm::IRBuilder<> irb(block);

  llvm::Value *mem_ptr = irb.CreateLoad(mem_ptr_ref);
  mem_ptr = decl.CallFromLiftedBlock(native_func->getName().str(), intrinsics,
                                     block, state_ptr, mem_ptr, true);
  irb.SetInsertPoint(block);
  irb.CreateStore(mem_ptr, mem_ptr_ref);
  return mem_ptr;
}

// Visit all instructions. This runs the work list and lifts instructions.
void FunctionLifterImpl::VisitInstructions(uint64_t address) {
  remill::Instruction inst;

  // Recursively decode and lift all instructions that we come across.
  while (!edge_work_list.empty()) {
    const auto [inst_addr, from_addr] = *(edge_work_list.begin());
    edge_work_list.erase(edge_work_list.begin());

    llvm::BasicBlock * const block = edge_to_dest_block[{from_addr, inst_addr}];
    DCHECK_NOTNULL(block);
    if (!block->empty()) {
      continue;  // Already handled.
    }

    // First, try to see if it's actually related to another function. This is
    // equivalent to a tail-call in the original code. This comes up with fall-
    // throughs, i.e. where one function is a prologue of another one. It also
    // happens with tail-calls, i.e. `jmp func` or `jCC func`, where we handle
    // those by way of enqueuing those addresses with `GetOrCreateBlock`, and
    // then recover from the tail-calliness here, instead of spreading that
    // logic into all the control-flow visitors.
    //
    // NOTE(pag): In the case of `inst_addr == func_address && from_addr != 0`,
    //            it means we have a control-flow edge or fall-through edge
    //            back to the entrypoint of our function. In this case, treat it
    //            like a tail-call.
    if (inst_addr != func_address || from_addr) {
      auto maybe_decl = type_provider.TryGetFunctionType(inst_addr);
      if (maybe_decl) {
        llvm::Function * const other_decl = DeclareFunction(*maybe_decl);

        if (const auto mem_ptr_from_call = TryCallNativeFunction(
                inst_addr, other_decl, block)) {
          llvm::ReturnInst::Create(context, mem_ptr_from_call, block);
          continue;
        }

        LOG(ERROR)
            << "Failed to call native function at " << std::hex << inst_addr
            << " via fall-through or tail call from function " << func_address
            << std::dec;

        // NOTE(pag): Recover by falling through and just try to decode/lift
        //            the instructions.
      }
    }

    llvm::BasicBlock *&inst_block = addr_to_block[inst_addr];
    if (!inst_block) {
      inst_block = block;

    // We've already lifted this instruction via another control-flow edge.
    } else {
      llvm::BranchInst::Create(inst_block, block);
      continue;
    }

    // Decode.
    if (!DecodeInstructionInto(inst_addr, false /* is_delayed */, &inst)) {
      LOG(ERROR) << "Could not decode instruction at " << std::hex << inst_addr
                 << " reachable from instruction " << from_addr
                 << " in function at " << func_address << std::dec;
      remill::AddTerminatingTailCall(block, intrinsics.error);
      continue;

    // Didn't get a valid instruction.
    } else if (!inst.IsValid() || inst.IsError()) {
      remill::AddTerminatingTailCall(block, intrinsics.error);
      continue;

    } else {
      VisitInstruction(inst, block);
    }
  }
}

// Declare the function decl `decl` and return an `llvm::Function *`.
llvm::Function *FunctionLifterImpl::GetOrDeclareFunction(
    const FunctionDecl &decl) {

  auto &native_func = addr_to_func[decl.address];
  if (native_func) {
    return native_func;
  }

  const auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, context));

  // By default we do not want to deal with function names until the very end of
  // lifting. Instead, we assign a temporary name based on the function's
  // starting address, its type, and its calling convention.
  std::stringstream ss;
  ss << "sub_" << std::hex << decl.address << '_'
     << TranslateType(*func_type, semantics_module->getDataLayout())
     << '_' << std::dec << decl.calling_convention;

  const auto base_name = ss.str();
  func_name_to_address.emplace(base_name, decl.address);

  // Try to get it as an already named function.
  native_func = semantics_module->getFunction(base_name);
  if (native_func) {
    return native_func;
  }

  native_func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, base_name,
      semantics_module.get());
  native_func->setCallingConv(decl.calling_convention);
  native_func->removeFnAttr(llvm::Attribute::InlineHint);
  native_func->removeFnAttr(llvm::Attribute::AlwaysInline);
  native_func->addFnAttr(llvm::Attribute::NoInline);
  return native_func;
}

// Allocate and initialize the state structure.
void FunctionLifterImpl::AllocateAndInitializeStateStructure(
    llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir(block);
  const auto state_type = state_ptr_type->getElementType();
  switch (options.state_struct_init_procedure) {
    case StateStructureInitializationProcedure::kNone:
      state_ptr = ir.CreateAlloca(state_type);
      break;
    case StateStructureInitializationProcedure::kZeroes:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::Constant::getNullValue(state_type), state_ptr);
      break;
    case StateStructureInitializationProcedure::kUndef:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::UndefValue::get(state_type), state_ptr);
      break;
    case StateStructureInitializationProcedure::kGlobalRegisterVariables:
      state_ptr = ir.CreateAlloca(state_type);
      InitializeStateStructureFromGlobalRegisterVariables(block);
      break;
    case StateStructureInitializationProcedure::kGlobalRegisterVariablesAndZeroes:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::Constant::getNullValue(state_type), state_ptr);
      InitializeStateStructureFromGlobalRegisterVariables(block);
      break;
    case StateStructureInitializationProcedure::kGlobalRegisterVariablesAndUndef:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::UndefValue::get(state_type), state_ptr);
      InitializeStateStructureFromGlobalRegisterVariables(block);
      break;
  }
}

// Initialize the state structure with default values, loaded from global
// variables. The purpose of these global variables is to show that there are
// some unmodelled external dependencies inside of a lifted function.
void FunctionLifterImpl::InitializeStateStructureFromGlobalRegisterVariables(
    llvm::BasicBlock *block) {

  // Get or create globals for all top-level registers. The idea here is that
  // the spec could feasibly miss some dependencies, and so after optimization,
  // we'll be able to observe uses of `__anvill_reg_*` globals, and handle
  // them appropriately.

  llvm::IRBuilder<> ir(block);

  options.arch->ForEachRegister([=, &ir](const remill::Register *reg_) {
    if (auto reg = reg_->EnclosingRegister(); reg_ == reg) {
      std::stringstream ss;
      ss << "__anvill_reg_" << reg->name;
      const auto reg_name = ss.str();

      auto reg_global = semantics_module->getGlobalVariable(reg_name);
      if (!reg_global) {
        reg_global = new llvm::GlobalVariable(
            *semantics_module, reg->type, false,
            llvm::GlobalValue::ExternalLinkage, nullptr, reg_name);
      }

      const auto reg_ptr = reg->AddressOf(state_ptr, block);
      ir.CreateStore(ir.CreateLoad(reg_global), reg_ptr);
    }
  });
}

// Initialize a symbolic program counter value in a lifted function. This
// mechanism is used to improve cross-reference discovery by using a
// relocatable constant expression as the initial value for a program counter.
// After optimizations, the net effect is that anything derived from this
// initial program counter is "tainted" by this initial constant expression,
// and therefore can be found.
llvm::Value *FunctionLifterImpl::InitializeSymbolicProgramCounter(
    llvm::BasicBlock *block) {

  auto pc_reg = options.arch->RegisterByName(
      options.arch->ProgramCounterRegisterName());
  auto pc_reg_ptr = pc_reg->AddressOf(state_ptr, block);

  auto base_pc = semantics_module->getGlobalVariable("__anvill_pc");
  if (!base_pc) {
    base_pc = new llvm::GlobalVariable(
        *semantics_module, i8_type, false, llvm::GlobalValue::ExternalLinkage,
        i8_zero, "__anvill_pc");
  }

  auto pc = llvm::ConstantExpr::getAdd(
      llvm::ConstantExpr::getPtrToInt(base_pc, pc_reg->type),
      llvm::ConstantInt::get(pc_reg->type, func_address, false));

  llvm::IRBuilder<> ir(block);
  ir.CreateStore(pc, pc_reg_ptr);
  return pc;
}

// Initialize the program value with a concrete integer address.
llvm::Value *FunctionLifterImpl::InitializeConcreteProgramCounter(
    llvm::BasicBlock *block) {
  auto pc_reg = options.arch->RegisterByName(
      options.arch->ProgramCounterRegisterName());
  auto pc_reg_ptr = pc_reg->AddressOf(state_ptr, block);
  auto pc = llvm::ConstantInt::get(pc_reg->type, func_address, false);
  llvm::IRBuilder<> ir(block);
  ir.CreateStore(pc, pc_reg_ptr);
  return pc;
}

// Initialize a symbolic stack pointer value in a lifted function. This
// mechanism is used to improve stack frame recovery, in a similar way that
// a symbolic PC improves cross-reference discovery.
void FunctionLifterImpl::InitialzieSymbolicStackPointer(llvm::BasicBlock *block) {
  auto sp_reg = options.arch->RegisterByName(
      options.arch->StackPointerRegisterName());
  auto sp_reg_ptr = sp_reg->AddressOf(state_ptr, block);

  auto base_sp = semantics_module->getGlobalVariable("__anvill_sp");
  if (!base_sp) {
    base_sp = new llvm::GlobalVariable(
        *semantics_module, i8_type, false, llvm::GlobalValue::ExternalLinkage,
        i8_zero, "__anvill_sp");
  }

  auto sp = llvm::ConstantExpr::getPtrToInt(base_sp, sp_reg->type);
  llvm::IRBuilder<> ir(block);
  ir.CreateStore(sp, sp_reg_ptr);
}

// Initialize a symbolic return address. This is similar to symbolic program
// counters/stack pointers.
llvm::Value *FunctionLifterImpl::InitializeSymbolicReturnAddress(
    llvm::BasicBlock *block, llvm::Value *mem_ptr,
    const ValueDecl &ret_address) {
  auto base_ra = semantics_module->getGlobalVariable("__anvill_ra");
  if (!base_ra) {
    base_ra = new llvm::GlobalVariable(
        *semantics_module, i8_type, false, llvm::GlobalValue::ExternalLinkage,
        i8_zero, "__anvill_ra");
  }

  auto pc_reg = options.arch->RegisterByName(
      options.arch->ProgramCounterRegisterName());
  auto ret_addr = llvm::ConstantExpr::getPtrToInt(base_ra, pc_reg->type);

  return StoreNativeValue(ret_addr, ret_address, intrinsics, block,
                          state_ptr, mem_ptr);
}

// Initialize a concrete return address. This is an intrinsic function call.
llvm::Value *FunctionLifterImpl::InitializeConcreteReturnAddress(
    llvm::BasicBlock *block, llvm::Value *mem_ptr,
    const ValueDecl &ret_address) {
  auto ret_addr_func = llvm::Intrinsic::getDeclaration(
      semantics_module.get(), llvm::Intrinsic::returnaddress);
  llvm::Value *args[] = {llvm::ConstantInt::get(i32_type, 0)};

  auto pc_reg = options.arch->RegisterByName(
      options.arch->ProgramCounterRegisterName());

  llvm::Value *ret_addr = llvm::CallInst::Create(
      ret_addr_func, args, llvm::None, llvm::Twine::createNull(),
      &(block->front()));

  llvm::IRBuilder<> ir(block);
  ret_addr = ir.CreatePtrToInt(ret_addr, pc_reg->type,
                               llvm::Twine::createNull());
  return StoreNativeValue(ret_addr, ret_address, intrinsics, block,
                          state_ptr, mem_ptr);
}

// Set up `native_func` to be able to call `lifted_func`. This means
// marshalling high-level argument types into lower-level values to pass into
// a stack-allocated `State` structure. This also involves providing initial
// default values for registers.
void FunctionLifterImpl::CallLiftedFunctionFromNativeFunction(void) {
  if (!native_func->isDeclaration()) {
    return;
  }

  // Get a `FunctionDecl` for `native_func`, which we can use to figure out
  // how to marshal its parameters into the emulated `State` and `Memory *`
  // of Remill lifted code, and marshal out the return value, if any.
  auto &decl = addr_to_decl[func_address];
  if (!decl.address) {
    auto maybe_decl = FunctionDecl::Create(*native_func, options.arch);
    if (remill::IsError(maybe_decl)) {
      LOG(ERROR)
          << "Unable to create FunctionDecl for "
          << remill::LLVMThingToString(native_func->getFunctionType())
          << " with calling convention " << native_func->getCallingConv()
          << ": " << remill::GetErrorString(maybe_decl);
      return;
    }

    decl = std::move(remill::GetReference(maybe_decl));
  }

  // Create a state structure and a stack frame in the native function
  // and we'll call the lifted function with that. The lifted function
  // will get inlined into this function.
  auto block = llvm::BasicBlock::Create(context, "", native_func);

  // Create a memory pointer.
  llvm::Value *mem_ptr = llvm::Constant::getNullValue(mem_ptr_type);

  // Stack-allocate and initialize the state pointer.
  AllocateAndInitializeStateStructure(block);

  llvm::Value *pc = nullptr;
  if (options.symbolic_program_counter) {
    pc = InitializeSymbolicProgramCounter(block);
  } else {
    pc = InitializeConcreteProgramCounter(block);
  }

  // Initialize the stack pointer.
  if (options.symbolic_stack_pointer) {
    InitialzieSymbolicStackPointer(block);
  }

  // Put the function's return address wherever it needs to go.
  if (options.symbolic_return_address) {
    mem_ptr = InitializeSymbolicReturnAddress(
        block, mem_ptr, decl.return_address);
  } else {
    mem_ptr = InitializeConcreteReturnAddress(
        block, mem_ptr, decl.return_address);
  }

  // Store the function parameters either into the state struct
  // or into memory (likely the stack).
  auto arg_index = 0u;
  for (auto &arg : native_func->args()) {
    const auto &param_decl = decl.params[arg_index++];
    mem_ptr = StoreNativeValue(&arg, param_decl, intrinsics, block, state_ptr,
                               mem_ptr);
  }

  llvm::IRBuilder<> ir(block);

  llvm::Value *lifted_func_args[remill::kNumBlockArgs] = {};
  lifted_func_args[remill::kStatePointerArgNum] = state_ptr;
  lifted_func_args[remill::kMemoryPointerArgNum] = mem_ptr;
  lifted_func_args[remill::kPCArgNum] = pc;
  auto call_to_lifted_func = ir.CreateCall(lifted_func, lifted_func_args);
  mem_ptr = call_to_lifted_func;

  llvm::Value *ret_val = nullptr;

  if (decl.returns.size() == 1) {
    ret_val = LoadLiftedValue(decl.returns.front(), intrinsics, block,
                              state_ptr, mem_ptr);
    ir.SetInsertPoint(block);

  } else if (1 < decl.returns.size()) {
    ret_val = llvm::UndefValue::get(native_func->getReturnType());
    auto index = 0u;
    for (auto &ret_decl : decl.returns) {
      auto partial_ret_val =
          LoadLiftedValue(ret_decl, intrinsics, block, state_ptr, mem_ptr);
      ir.SetInsertPoint(block);
      unsigned indexes[] = {index};
      ret_val = ir.CreateInsertValue(ret_val, partial_ret_val, indexes);
      index += 1;
    }
  }

  auto memory_escape = GetMemoryEscapeFunc(intrinsics);
  llvm::Value *escape_args[] = {mem_ptr};
  ir.CreateCall(memory_escape, escape_args);

  if (ret_val) {
    ir.CreateRet(ret_val);
  } else {
    ir.CreateRetVoid();
  }
}

// In practice, lifted functions are not workable as is; we need to emulate
// `__attribute__((flatten))`, i.e. recursively inline as much as possible, so
// that all semantics and helpers are completely inlined.
void FunctionLifterImpl::RecursivelyInlineLiftedFunctionIntoNativeFunction(void) {
  std::vector<llvm::CallInst *> calls_to_inline;
  for (auto changed = true; changed; changed = !calls_to_inline.empty()) {
    calls_to_inline.clear();

    for (auto &block : *native_func) {
      for (auto &inst : block) {
        if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst); call_inst) {
          if (auto called_func = call_inst->getCalledFunction();
              called_func && !called_func->isDeclaration() &&
              !called_func->hasFnAttribute(llvm::Attribute::NoInline)) {
            calls_to_inline.push_back(call_inst);
          }
        }
      }
    }

    for (auto call_inst : calls_to_inline) {
      llvm::InlineFunctionInfo info;
      InlineFunction(call_inst, info);
    }
  }

  // Initialize cleanup optimizations
  llvm::legacy::FunctionPassManager fpm(semantics_module.get());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createPromoteMemoryToRegisterPass());
  fpm.add(llvm::createReassociatePass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createSROAPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createInstructionCombiningPass());
  fpm.doInitialization();
  fpm.run(*native_func);
  fpm.doFinalization();

  ClearVariableNames(native_func);
}

// Lift a function. Will return `nullptr` if the memory is
// not accessible or executable.
llvm::Function *FunctionLifterImpl::DeclareFunction(const FunctionDecl &decl) {

  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      memory_provider.Query(decl.address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail) ||
      !MemoryProvider::IsExecutable(first_byte_perms)) {
    return nullptr;
  }

  // This is our higher-level function, i.e. it presents itself more like
  // a function compiled from C/C++, rather than being a three-argument Remill
  // function. In this function, we will stack-allocate a `State` structure,
  // then call a `lifted_func` below, which will embed the instruction
  // semantics.
  return GetOrDeclareFunction(decl);
}

// Lift a function. Will return `nullptr` if the memory is
// not accessible or executable.
llvm::Function *FunctionLifterImpl::LiftFunction(const FunctionDecl &decl) {

  addr_to_decl.clear();
  addr_to_func.clear();
  edge_work_list.clear();
  edge_to_dest_block.clear();
  addr_to_block.clear();
  inst_lifter.ClearCache();
  curr_inst = nullptr;
  state_ptr = nullptr;
  func_address = decl.address;
  native_func = DeclareFunction(decl);

  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      memory_provider.Query(func_address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail) ||
      !MemoryProvider::IsExecutable(first_byte_perms)) {
    return nullptr;
  }

  // This is our higher-level function, i.e. it presents itself more like
  // a function compiled from C/C++, rather than being a three-argument Remill
  // function. In this function, we will stack-allocate a `State` structure,
  // then call a `lifted_func` below, which will embed the instruction
  // semantics.
  native_func = GetOrDeclareFunction(decl);

  // Check if we already lifted this function. If so, do not re-lift it.
  if (!native_func->isDeclaration()) {
    return native_func;
  }

  // The address is valid, the memory is executable, but we don't actually have
  // the data available for lifting, so leave us with just a declaration.
  if (!MemoryProvider::HasByte(first_byte_avail)) {
    return native_func;
  }

  // Every lifted function starts as a clone of __remill_basic_block. That
  // prototype has multiple arguments (memory pointer, state pointer, program
  // counter). This extracts the state pointer.
  lifted_func = remill::DeclareLiftedFunction(
      semantics_module.get(), native_func->getName().str() + ".lifted");

  state_ptr = remill::NthArgument(lifted_func, remill::kStatePointerArgNum);
  CHECK(lifted_func->isDeclaration());

  remill::CloneBlockFunctionInto(lifted_func);
  lifted_func->removeFnAttr(llvm::Attribute::NoInline);
  lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);
  lifted_func->setLinkage(llvm::GlobalValue::InternalLinkage);

  // Add a branch between the first block of the lifted function, which sets
  // up some local variables, and the block that will contain the lifted
  // instruction.
  //
  // NOTE(pag): This also introduces the first element to the work list.
  llvm::BranchInst::Create(GetOrCreateBlock(func_address),
                           &(lifted_func->getEntryBlock()));

  // Go lift all instructions!
  VisitInstructions(func_address);

  // Fill up `native_func` with a basic block and make it call `lifted_func`.
  // This creates things like the stack-allocated `State` structure.
  CallLiftedFunctionFromNativeFunction();

  // The last stage is that we need to recursively inline all calls to semantics
  // functions into `native_func`.
  RecursivelyInlineLiftedFunctionIntoNativeFunction();

  return native_func;
}

// Returns the address of a named function.
std::optional<uint64_t> FunctionLifterImpl::AddressOfNamedFunction(
    const std::string &func_name) const {
  auto it = func_name_to_address.find(func_name);
  if (it == func_name_to_address.end()) {
    return std::nullopt;
  } else {
    return it->second;
  }
}

FunctionLifter::~FunctionLifter(void) {}

FunctionLifter::FunctionLifter(const Context &entity_lfiter_)
    : impl(entity_lfiter_.impl) {}

// Lifts the machine code function starting at address `address`, and using
// `options_.arch` as the architecture for lifting, into `options_.module`.
// Returns an `llvm::Function *` that is part of `options_.module`.
llvm::Function *FunctionLifter::LiftFunction(const FunctionDecl &decl) const {
  const auto func = impl->function_lifter.LiftFunction(decl);
  if (func) {
    AddFunctionToContext(func, decl.address);
  }
  return func;
}

// Declare the function associated with `decl` in the context's module.
llvm::Function *FunctionLifter::DeclareFunction(
    const FunctionDecl &decl) const {
  const auto func = impl->function_lifter.DeclareFunction(decl);
  if (func) {
    if (auto existing_func =
            impl->options.module->getFunction(func->getName())) {
      impl->AddFunction(func, decl.address);
      return existing_func;

    } else {
      AddFunctionToContext(func, decl.address);
    }
  }
  return func;
}

// Update the associated context (`impl`) with information about this
// function, and move the function into the context's module.
void FunctionLifter::AddFunctionToContext(llvm::Function *func,
                                          uint64_t address) const {
  auto &func_lifter = impl->function_lifter;
  const auto semantics_module = func_lifter.semantics_module.get();
  const auto target_module = impl->options.module;

  auto &semantics_context = semantics_module->getContext();
  auto &module_context = target_module->getContext();
  const auto name = func->getName().str();

  llvm::Function *new_version = nullptr;

  // Now that we've lifted the function, we're left with some pretty brutal
  // bitcode, and its in the wrong module too. So, we need to go and move or
  // copy the lifted function into the target module.
  if (&semantics_context == &module_context) {
    remill::MoveFunctionIntoModule(func, target_module);
    new_version = target_module->getFunction(name);

  } else {
    const auto module_func_type = llvm::dyn_cast<llvm::FunctionType>(
        remill::RecontextualizeType(func->getFunctionType(), module_context));

    new_version = llvm::Function::Create(
        module_func_type, llvm::GlobalValue::ExternalLinkage, name,
        target_module);

    remill::CloneFunctionInto(func, new_version);
  }

  // Update the context to keep its internal concepts of what LLVM objects
  // correspond with which native binary addresses.
  impl->AddFunction(new_version, address);
}

}  // namespace anvill
