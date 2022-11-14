/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "FunctionLifter.h"

#include <anvill/ABI.h>
#include <anvill/Providers.h>
#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Pass.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <variant>

#include "EntityLifter.h"

namespace anvill {
namespace {

// Clear out LLVM variable names. They're usually not helpful.
static void ClearVariableNames(llvm::Function *func) {
  for (auto &block : *func) {
    //    block.setName(llvm::Twine::createNull());
    for (auto &inst : block) {
      if (inst.hasName()) {
        inst.setName(llvm::Twine::createNull());
      }
    }
  }
}


// A function that ensures that the memory pointer escapes, and thus none of
// the memory writes at the end of a function are lost.
static llvm::Function *
GetMemoryEscapeFunc(const remill::IntrinsicTable &intrinsics) {
  const auto module = intrinsics.error->getParent();
  auto &context = module->getContext();

  if (auto func = module->getFunction(kMemoryPointerEscapeFunction)) {
    return func;
  }

  llvm::Type *params[] = {
      remill::NthArgument(intrinsics.error, remill::kMemoryPointerArgNum)
          ->getType()};
  auto type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), params, false);
  return llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage,
                                kMemoryPointerEscapeFunction.data(), module);
}

// We're calling a remill intrinsic and we want to "mute" the escape of the
// `State` pointer by replacing it with an `undef` value. This permits
// optimizations while allowing us to still observe what reaches the `pc`
// argument of the intrinsic. This is valuable for function return intrinsics,
// because it lets us verify that the value that we initialize into the return
// address location actually reaches the `pc` parameter of the
// `__remill_function_return`.
static void MuteStateEscape(llvm::CallInst *call) {
  auto state_ptr_arg = call->getArgOperand(remill::kStatePointerArgNum);
  auto undef_val = llvm::UndefValue::get(state_ptr_arg->getType());
  call->setArgOperand(remill::kStatePointerArgNum, undef_val);
}

// This returns a special anvill built-in used to describe jumps tables
// inside lifted code; It takes the address type to generate the function
// parameters of correct type.
static llvm::Function *GetAnvillSwitchFunc(llvm::Module &module,
                                           llvm::Type *type) {

  const auto &func_name = kAnvillSwitchCompleteFunc;

  auto func = module.getFunction(func_name);
  if (func != nullptr) {
    return func;
  }

  llvm::Type *func_parameters[] = {type};

  auto func_type = llvm::FunctionType::get(type, func_parameters, true);

  func = llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                                func_name, module);

  func->addFnAttr(llvm::Attribute::ReadNone);

  return func;
}

// Annotate and instruction with the `id` annotation if that instruction
// is unannotated.
static void AnnotateInstruction(llvm::Instruction *inst, unsigned id,
                                llvm::MDNode *annot) {
  if (annot && !inst->getMetadata(id)) {
    inst->setMetadata(id, annot);
  }
}

static void AnnotateInstruction(llvm::Value *val, unsigned id,
                                llvm::MDNode *annot) {
  if (auto inst = llvm::dyn_cast<llvm::Instruction>(val)) {
    if (!inst->getMetadata(id)) {
      inst->setMetadata(id, annot);
    }
  }
}

// Annotate and instruction with the `id` annotation if that instruction
// is unannotated.
static void AnnotateInstructions(llvm::BasicBlock *block, unsigned id,
                                 llvm::MDNode *annot) {
  if (annot) {
    for (auto &inst : *block) {
      AnnotateInstruction(&inst, id, annot);
    }
  }
}

}  // namespace

FunctionLifter::~FunctionLifter(void) {}

FunctionLifter::FunctionLifter(const LifterOptions &options_)
    : options(options_),
      memory_provider(options.memory_provider),
      type_provider(options.type_provider),
      type_specifier(options.TypeDictionary(), options.arch),
      semantics_module(remill::LoadArchSemantics(options.arch)),
      llvm_context(semantics_module->getContext()),
      intrinsics(semantics_module.get()),
      op_lifter(options.arch->DefaultLifter(intrinsics)),
      pc_reg(options.arch
                 ->RegisterByName(options.arch->ProgramCounterRegisterName())
                 ->EnclosingRegister()),
      sp_reg(
          options.arch->RegisterByName(options.arch->StackPointerRegisterName())
              ->EnclosingRegister()),
      is_sparc(options.arch->IsSPARC32() || options.arch->IsSPARC64()),
      is_x86_or_amd64(options.arch->IsX86() || options.arch->IsAMD64()),
      i8_type(llvm::Type::getInt8Ty(llvm_context)),
      i8_zero(llvm::Constant::getNullValue(i8_type)),
      i32_type(llvm::Type::getInt32Ty(llvm_context)),
      mem_ptr_type(
          llvm::dyn_cast<llvm::PointerType>(remill::RecontextualizeType(
              options.arch->MemoryPointerType(), llvm_context))),
      state_ptr_type(
          llvm::dyn_cast<llvm::PointerType>(remill::RecontextualizeType(
              options.arch->StatePointerType(), llvm_context))),
      address_type(
          llvm::Type::getIntNTy(llvm_context, options.arch->address_size)),
      pc_reg_type(pc_reg->type) {

  if (options.pc_metadata_name) {
    pc_annotation_id = llvm_context.getMDKindID(options.pc_metadata_name);
  }
}


llvm::BranchInst *
FunctionLifter::BranchToInst(uint64_t from_addr, uint64_t to_addr,
                             const remill::DecodingContext &mapper,
                             llvm::BasicBlock *from_block) {
  auto br = llvm::BranchInst::Create(
      GetOrCreateBlock(from_addr, to_addr, mapper), from_block);
  AnnotateInstruction(br, pc_annotation_id, pc_annotation);
  return br;
}

// Helper to get the basic block to contain the instruction at `addr`. This
// function drives a work list, where the first time we ask for the
// instruction at `addr`, we enqueue a bit of work to decode and lift that
// instruction.
llvm::BasicBlock *
FunctionLifter::GetOrCreateBlock(uint64_t from_addr, uint64_t to_addr,
                                 const remill::DecodingContext &mapper) {
  auto &block = edge_to_dest_block[{from_addr, to_addr}];
  if (block) {
    return block;
  }

  std::stringstream ss;
  ss << "inst_" << std::hex << to_addr;
  block = llvm::BasicBlock::Create(llvm_context, ss.str(), lifted_func);

  // NOTE(pag): We always add to the work list without consulting/updating
  //            `addr_to_block` so that we can observe self-tail-calls and
  //            lift them as such, rather than as jumps back into the first
  //            lifted block.
  edge_work_list.emplace(to_addr, from_addr);
  this->decoding_contexts.emplace(std::make_pair(to_addr, from_addr), mapper);
  return block;
}

llvm::BasicBlock *
FunctionLifter::GetOrCreateTargetBlock(const remill::Instruction &from_inst,
                                       uint64_t to_addr,
                                       const remill::DecodingContext &mapper) {
  return GetOrCreateBlock(from_inst.pc, to_addr, mapper);
}

// Try to decode an instruction at address `addr` into `*inst_out`. Returns
// the context map of the decoded instruction if successful and std::nullopt otherwise. `is_delayed` tells the decoder
// whether or not the instruction being decoded is being decoded inside of a
// delay slot of another instruction.
bool FunctionLifter::DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                                           remill::Instruction *inst_out,
                                           remill::DecodingContext context) {
  static const auto max_inst_size = options.arch->MaxInstructionSize(context);
  inst_out->Reset();

  // Read the maximum number of bytes possible for instructions on this
  // architecture. For x86(-64), this is 15 bytes, whereas for fixed-width
  // architectures like AArch32/AArch64 and SPARC32/SPARC64, this is 4 bytes.
  inst_out->bytes.reserve(max_inst_size);

  auto accumulate_inst_byte = [=](auto byte, auto accessible, auto perms) {
    switch (accessible) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kUnavailable: return false;
      default:
        switch (perms) {
          case BytePermission::kUnknown:
          case BytePermission::kReadableExecutable:
          case BytePermission::kReadableWritableExecutable:
            inst_out->bytes.push_back(static_cast<char>(byte));
            return true;
          case BytePermission::kReadable:
          case BytePermission::kReadableWritable: return false;
        }
    }
  };

  for (auto i = 0u; i < max_inst_size; ++i) {
    if (!std::apply(accumulate_inst_byte, memory_provider.Query(addr + i))) {
      break;
    }
  }

  if (is_delayed) {
    return options.arch->DecodeDelayedInstruction(
        addr, inst_out->bytes, *inst_out, std::move(context));
  } else {
    DLOG(INFO) << "Ops emplace: " << inst_out->operands.size();
    return options.arch->DecodeInstruction(addr, inst_out->bytes, *inst_out,
                                           std::move(context));
  }
}

// Visit an invalid instruction. An invalid instruction is a sequence of
// bytes which cannot be decoded, or an empty byte sequence.
void FunctionLifter::VisitInvalid(const remill::Instruction &inst,
                                  llvm::BasicBlock *block) {
  MuteStateEscape(
      remill::AddTerminatingTailCall(block, intrinsics.error, intrinsics));
}

// Visit an error instruction. An error instruction is guaranteed to trap
// execution somehow, e.g. `ud2` on x86. Error instructions are treated
// similarly to invalid instructions, with the exception that they can have
// delay slots, and therefore the subsequent instruction may actually execute
// prior to the error.
void FunctionLifter::VisitError(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  MuteStateEscape(
      remill::AddTerminatingTailCall(block, intrinsics.error, intrinsics));
}

void FunctionLifter::InsertError(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir{block};
  auto tail = remill::AddTerminatingTailCall(
      ir.GetInsertBlock(), intrinsics.error, this->intrinsics);
  AnnotateInstruction(tail, pc_annotation_id, pc_annotation);
  AnnotateInstruction(tail, pc_annotation_id, pc_annotation);
}

// Visit a normal instruction. Normal instructions have straight line control-
// flow semantics, i.e. after executing the instruction, execution proceeds
// to the next instruction (`inst.next_pc`).
void FunctionLifter::VisitNormal(
    const remill::Instruction &inst, llvm::BasicBlock *block,
    const remill::Instruction::NormalInsn &mapper) {
  auto cf = options.control_flow_provider.GetControlFlowOverride(inst.pc);
  bool stop = false;

  if (std::holds_alternative<Misc>(cf)) {
    auto spec = std::get<Misc>(cf);
    stop = spec.stop;
  } else if (!std::holds_alternative<std::monostate>(cf)) {
    LOG(ERROR)
        << "Found invalid control flow override for normal instruction at "
        << std::hex << inst.pc;
  }

  if (stop) {
    InsertError(block);
  } else {
    llvm::BranchInst::Create(
        GetOrCreateTargetBlock(inst, inst.next_pc,
                               mapper.fallthrough.fallthrough_context),
        block);
  }
}

// Visit a no-op instruction. These behave identically to normal instructions
// from a control-flow perspective.
void FunctionLifter::VisitNoOp(const remill::Instruction &inst,
                               llvm::BasicBlock *block,
                               const remill::Instruction::NoOp &mapper) {
  VisitNormal(inst, block, mapper.fallthrough);
}

// Visit a direct jump control-flow instruction. The target of the jump is
// known at decode time, and the target address is available in
// `inst.branch_taken_pc`. Execution thus needs to transfer to the instruction
// (and thus `llvm::BasicBlock`) associated with `inst.branch_taken_pc`.
void FunctionLifter::VisitDirectJump(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block,
    const remill::Instruction::DirectJump &mapper) {
  auto cf = options.control_flow_provider.GetControlFlowOverride(inst.pc);
  if (std::holds_alternative<Jump>(cf)) {
    auto jmp_spec = std::get<Jump>(cf);

    if (jmp_spec.targets.size() != 1) {
      LOG(FATAL) << "Invalid number of targets for direct jump at " << std::hex
                 << inst.pc;
    }

    CHECK_EQ(mapper.taken_flow.known_target, jmp_spec.targets[0].address)
        << "Spec and remill don't agree on jump target at " << std::hex
        << inst.pc;
    VisitDelayedInstruction(inst, delayed_inst, block, true);
    llvm::BranchInst::Create(
        GetOrCreateTargetBlock(inst, mapper.taken_flow.known_target,
                               mapper.taken_flow.static_context),
        block);
  } else if (std::holds_alternative<Call>(cf)) {
    VisitDelayedInstruction(inst, delayed_inst, block, true);
    CallFunction(inst, block, inst.branch_taken_pc);
    InsertError(block);
  } else {
    LOG(FATAL) << "Invalid spec for direct jump at " << std::hex << inst.pc;
  }
}

remill::DecodingContext FunctionLifter::ApplyTargetList(
    const std::unordered_map<std::string, uint64_t> &assignments,
    remill::DecodingContext prev_context) {
  for (const auto &[k, v] : assignments) {
    prev_context.UpdateContextReg(k, v);
  }
  return prev_context;
}

// Visit an indirect jump that is a jump table.
void FunctionLifter::DoSwitchBasedIndirectJump(
    const remill::Instruction &inst, llvm::BasicBlock *block,
    const std::vector<JumpTarget> &target_list,
    const remill::Instruction::IndirectJump &mapper,
    const remill::DecodingContext &prev_context) {

  auto add_remill_jump{true};
  llvm::BasicBlock *current_bb = block;

  // This is a list of the possibilities we want to cover:
  //
  // 1. No target: AddTerminatingTailCall
  // 2. Single target, complete: normal jump
  // 3. Multiple targets, complete: switch with no default case
  // 4. Single or multiple targets, not complete: switch with default case
  //    containing AddTerminatingTailCall


  // If the target list is complete and has only one destination, then we
  // can handle it as normal jump
  if (target_list.size() == 1U) {
    add_remill_jump = false;

    auto destination = target_list[0];


    llvm::BranchInst::Create(
        GetOrCreateTargetBlock(
            inst, destination.address,
            this->ApplyTargetList(destination.context_assignments,
                                  prev_context)),
        block);

    // We have multiple destinations. Handle this with a switch. If the target
    // list is not marked as complete, then we'll still add __remill_jump
    // inside the default block
  } else {
    llvm::BasicBlock *default_case{nullptr};

    // Create a default case that is not reachable
    add_remill_jump = false;
    default_case = llvm::BasicBlock::Create(llvm_context, "", lifted_func);

    llvm::IRBuilder<> builder(default_case);
    builder.CreateUnreachable();

    // Create the parameters for the special anvill switch
    auto pc = this->op_lifter->LoadRegValue(
        block, state_ptr, options.arch->ProgramCounterRegisterName());

    std::vector<llvm::Value *> switch_parameters;
    switch_parameters.push_back(pc);

    for (auto destination : target_list) {
      switch_parameters.push_back(
          llvm::ConstantInt::get(pc_reg->type, destination.address));
    }

    // Invoke the anvill switch
    auto &module = *block->getModule();
    auto anvill_switch_func = GetAnvillSwitchFunc(module, address_type);

    llvm::IRBuilder<> ir(block);
    auto next_pc = ir.CreateCall(anvill_switch_func, switch_parameters);

    // Now use the anvill switch output with a SwitchInst, mapping cases
    // by index
    auto dest_count = target_list.size();
    auto switch_inst = ir.CreateSwitch(next_pc, default_case, dest_count);
    auto dest_id{0u};

    for (auto dest : target_list) {
      auto dest_block = GetOrCreateTargetBlock(
          inst, dest.address,
          this->ApplyTargetList(dest.context_assignments, prev_context));
      auto dest_case = llvm::ConstantInt::get(address_type, dest_id++);
      switch_inst->addCase(dest_case, dest_block);
    }

    AnnotateInstruction(next_pc, pc_annotation_id, pc_annotation);
    AnnotateInstruction(switch_inst, pc_annotation_id, pc_annotation);
  }

  if (add_remill_jump) {

    // Either we didn't find any target list from the control flow provider, or
    // we did but it wasn't marked as `complete`.
    auto jump =
        remill::AddTerminatingTailCall(current_bb, intrinsics.jump, intrinsics);
    AnnotateInstruction(jump, pc_annotation_id, pc_annotation);
  }
}

// Visit an indirect jump control-flow instruction. This may be register- or
// memory-indirect, e.g. `jmp rax` or `jmp [rax]` on x86. Thus, the target is
// not know a priori and our default mechanism for handling this is to perform
// a tail-call to the `__remill_jump` function, whose role is to be a stand-in
// something that enacts the effect of "transfer to target."
void FunctionLifter::VisitIndirectJump(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block,
    const remill::Instruction::IndirectJump &mapper,
    const remill::DecodingContext &prev_context) {
  auto cf = options.control_flow_provider.GetControlFlowOverride(inst.pc);
  if (std::holds_alternative<Jump>(cf)) {
    auto jmp_spec = std::get<Jump>(cf);

    VisitDelayedInstruction(inst, delayed_inst, block, true);

    // Try to get the target type given the source. This is like a tail-call,
    // e.g. `jmp [fseek]`.
    if (auto maybe_decl =
            type_provider.TryGetCalledFunctionType(func_address, inst)) {
      llvm::IRBuilder<> ir(block);
      llvm::Value *dest_addr = ir.CreateLoad(pc_reg_type, pc_reg_ref);
      AnnotateInstruction(dest_addr, pc_annotation_id, pc_annotation);
      auto new_mem_ptr =
          CallCallableDecl(block, dest_addr, std::move(maybe_decl.value()));
      ir.CreateRet(new_mem_ptr);

      // Attempt to get the target list for this control flow instruction
      // so that we can handle this jump in a less generic way.
    } else if (jmp_spec.targets.size() > 0) {

      DoSwitchBasedIndirectJump(inst, block, jmp_spec.targets, mapper,
                                prev_context);

      // No good info; do an indirect jump.
    } else {
      auto jump =
          remill::AddTerminatingTailCall(block, intrinsics.jump, intrinsics);
      AnnotateInstruction(jump, pc_annotation_id, pc_annotation);
    }
  } else if (std::holds_alternative<Call>(cf)) {
    VisitDelayedInstruction(inst, delayed_inst, block, true);
    CallFunction(inst, block, std::nullopt);
    InsertError(block);
  } else if (std::holds_alternative<Return>(cf)) {
    // TODO(Ian): It feels like we should be able to handle overrides/control flow much more uniformally, I think it would be good to do so in
    // a separate PR.
    this->VisitFunctionReturn(inst, delayed_inst, block);
  } else {
    LOG(FATAL) << "Invalid spec for indirect jump at " << std::hex << inst.pc;
  }
}

void FunctionLifter::VisitConditionalInstruction(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block,
    const remill::Instruction::ConditionalInstruction &conditional_insn,
    const remill::DecodingContext &prev_context) {

  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);
  const auto not_taken_block =
      llvm::BasicBlock::Create(llvm_context, "", lifted_func);

  auto cond_jump_fallthrough_br =
      llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);

  FlowVisitor visitor = {*this, inst, taken_block, delayed_inst, prev_context};
  std::visit(visitor, conditional_insn.taken_branch);

  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);


  auto fallthrough_br = llvm::BranchInst::Create(
      GetOrCreateTargetBlock(inst, inst.next_pc,
                             conditional_insn.fall_through.fallthrough_context),
      not_taken_block);

  AnnotateInstruction(cond_jump_fallthrough_br, pc_annotation_id,
                      pc_annotation);
  AnnotateInstruction(fallthrough_br, pc_annotation_id, pc_annotation);
}

// Visit a function return control-flow instruction, which is a form of
// indirect control-flow, but with a certain semantic associated with
// returning from a function. This is treated similarly to indirect jumps,
// except the `__remill_function_return` function is tail-called.
void FunctionLifter::VisitFunctionReturn(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  auto func_return = remill::AddTerminatingTailCall(
      block, intrinsics.function_return, intrinsics);
  AnnotateInstruction(func_return, pc_annotation_id, pc_annotation);
  MuteStateEscape(func_return);
}

std::optional<CallableDecl>
FunctionLifter::TryGetTargetFunctionType(const remill::Instruction &from_inst,
                                         std::uint64_t address) {
  std::optional<CallableDecl> opt_callable_decl =
      type_provider.TryGetCalledFunctionTypeOrDefault(func_address, from_inst,
                                                      address);

  return opt_callable_decl;
}

// Call `pc` in `block`, treating it as a callable declaration `decl`.
llvm::Value *FunctionLifter::CallCallableDecl(llvm::BasicBlock *block,
                                              llvm::Value *pc,
                                              CallableDecl decl) {
  llvm::IRBuilder<> ir(block);
  CHECK_NOTNULL(decl.type);
  CHECK_EQ(decl.arch, options.arch);

  auto &context = block->getContext();

  auto dest_func =
      ir.CreateBitOrPointerCast(pc, llvm::PointerType::get(context, 0));

  auto mem_ptr = ir.CreateLoad(mem_ptr_type, mem_ptr_ref);
  auto new_mem_ptr =
      decl.CallFromLiftedBlock(dest_func, type_specifier.Dictionary(),
                               intrinsics, block, state_ptr, mem_ptr);
  auto store = ir.CreateStore(new_mem_ptr, mem_ptr_ref);

  AnnotateInstruction(dest_func, pc_annotation_id, pc_annotation);
  AnnotateInstruction(mem_ptr, pc_annotation_id, pc_annotation);
  AnnotateInstruction(new_mem_ptr, pc_annotation_id, pc_annotation);
  AnnotateInstruction(store, pc_annotation_id, pc_annotation);

  return new_mem_ptr;
}

// Try to resolve `inst.branch_taken_pc` to a lifted function, and introduce
// a function call to that address in `block`. Failing this, add a call
// to `__remill_function_call`.
bool FunctionLifter::CallFunction(const remill::Instruction &inst,
                                  llvm::BasicBlock *block,
                                  std::optional<std::uint64_t> target_pc) {
  auto cf = options.control_flow_provider.GetControlFlowOverride(inst.pc);
  if (!std::holds_alternative<Call>(cf)) {
    LOG(FATAL) << "Invalid spec for call at " << std::hex << inst.pc;
  }
  auto call_spec = std::get<Call>(cf);
  std::optional<CallableDecl> maybe_decl;

  if (call_spec.target_address.has_value()) {
    // First, try to see if it's actually related to another function. This is
    // equivalent to a tail-call in the original code.
    auto redirected_addr = *call_spec.target_address;

    // Now, get the type of the target given the source and destination.
    maybe_decl = TryGetTargetFunctionType(inst, redirected_addr);
    target_pc = redirected_addr;
  } else if (target_pc.has_value()) {

    maybe_decl =
        type_provider.TryGetCalledFunctionType(func_address, inst, *target_pc);
  } else {

    // If we don't know a concrete target address, then just try to get the
    // target given the source.
    maybe_decl = type_provider.TryGetCalledFunctionType(func_address, inst);
  }

  if (!maybe_decl) {
    LOG(ERROR) << "Missing type information for function called at address "
               << std::hex << inst.pc << " in function at address "
               << func_address << std::dec;

    // If we do not have a function declaration, treat this as a call
    // to an unknown address.
    auto call = remill::AddCall(block, intrinsics.function_call, intrinsics);
    AnnotateInstruction(call, pc_annotation_id, pc_annotation);
    return true;
  }


  llvm::IRBuilder<> ir(block);
  llvm::Value *dest_addr = nullptr;

  if (target_pc) {
    dest_addr =
        options.program_counter_init_procedure(ir, pc_reg, target_pc.value());
  } else {
    dest_addr = ir.CreateLoad(pc_reg_type, pc_reg_ref);
  }

  AnnotateInstruction(dest_addr, pc_annotation_id, pc_annotation);
  auto is_noreturn = maybe_decl->is_noreturn;
  (void) CallCallableDecl(block, dest_addr, std::move(maybe_decl.value()));
  return !is_noreturn;
}

// Visit a direct function call control-flow instruction. The target is known
// at decode time, and its realized address is stored in
// `inst.branch_taken_pc`. In practice, what we do in this situation is try
// to call the lifted function function at the target address.
void FunctionLifter::VisitDirectFunctionCall(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block,
    const remill::Instruction::DirectFunctionCall &dcall,
    const remill::DecodingContext &prev_context) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  bool can_return = CallFunction(inst, block, inst.branch_taken_pc);
  VisitAfterFunctionCall(inst, block, dcall, can_return, prev_context);
}


// Visit an indirect function call control-flow instruction. Similar to
// indirect jumps, we invoke an intrinsic function, `__remill_function_call`;
// however, unlike indirect jumps, we do not tail-call this intrinsic, and
// we continue lifting at the instruction where execution will resume after
// the callee returns. Thus, lifted bitcode maintains the call graph structure
// as it presents itself in the binary.
void FunctionLifter::VisitIndirectFunctionCall(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block,
    const remill::Instruction::IndirectFunctionCall &icall,
    const remill::DecodingContext &prev_context) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);
  bool can_return = CallFunction(inst, block, std::nullopt);
  VisitAfterFunctionCall(inst, block, icall, can_return, prev_context);
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
FunctionLifter::LoadFunctionReturnAddress(const remill::Instruction &inst,
                                          llvm::BasicBlock *block) {

  const auto pc = inst.branch_not_taken_pc;

  // The semantics for handling a call save the expected return program counter
  // into a local variable.
  auto ret_pc = this->op_lifter->LoadRegValue(block, state_ptr,
                                              remill::kReturnPCVariableName);
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

      default: bytes[i] = byte; break;
    }

    switch (perms) {
      case BytePermission::kUnknown:
      case BytePermission::kReadableExecutable:
      case BytePermission::kReadableWritableExecutable: break;
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
  // the size of the value to return. See "Specificationming Note" in v8 manual,
  // B.31, p 137.
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

// Enact relevant control-flow changes after a function call. This figures
// out the return address targeted by the callee and links it into the
// control-flow graph.
void FunctionLifter::VisitAfterFunctionCall(
    const remill::Instruction &inst, llvm::BasicBlock *block,
    const std::variant<remill::Instruction::IndirectFunctionCall,
                       remill::Instruction::DirectFunctionCall> &call,
    bool can_return, const remill::DecodingContext &prev_context) {
  const auto [ret_pc, ret_pc_val] = LoadFunctionReturnAddress(inst, block);

  llvm::IRBuilder<> ir(block);
  if (can_return) {
    auto update_pc = ir.CreateStore(ret_pc_val, pc_reg_ref, false);
    auto update_next_pc = ir.CreateStore(ret_pc_val, next_pc_reg_ref, false);
    auto branch_to_next_pc =
        ir.CreateBr(GetOrCreateTargetBlock(inst, ret_pc, prev_context));

    AnnotateInstruction(update_pc, pc_annotation_id, pc_annotation);
    AnnotateInstruction(update_next_pc, pc_annotation_id, pc_annotation);
    AnnotateInstruction(branch_to_next_pc, pc_annotation_id, pc_annotation);
  } else {
    auto tail = remill::AddTerminatingTailCall(
        ir.GetInsertBlock(), intrinsics.error, this->intrinsics);
    AnnotateInstruction(tail, pc_annotation_id, pc_annotation);
    AnnotateInstruction(tail, pc_annotation_id, pc_annotation);
  }
}


// Visit an asynchronous hyper call control-flow instruction. These are non-
// local control-flow transfers, such as system calls. We treat them like
// indirect function calls.
void FunctionLifter::VisitAsyncHyperCall(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.async_hyper_call,
                                 intrinsics);
}

// Visit (and thus lift) a delayed instruction. When lifting a delayed
// instruction, we need to know if we're one the taken path of a control-flow
// edge, or on the not-taken path. Delayed instructions appear physically
// after some instructions, but execute logically before them in the
// CPU pipeline. They are basically a way for hardware designers to push
// the effort of keeping the pipeline full to compiler developers.
void FunctionLifter::VisitDelayedInstruction(
    const remill::Instruction &inst,
    std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block,
    bool on_taken_path) {
  if (delayed_inst && options.arch->NextInstructionIsDelayed(
                          inst, *delayed_inst, on_taken_path)) {
    const auto prev_pc_annotation = pc_annotation;
    pc_annotation = GetPCAnnotation(delayed_inst->pc);
    inst.GetLifter()->LiftIntoBlock(*delayed_inst, block, state_ptr, true);
    AnnotateInstructions(block, pc_annotation_id, pc_annotation);
    pc_annotation = prev_pc_annotation;
  }
}

// Instrument an instruction. This inject a `printf`-like function call just
// before a lifted instruction to aid in tracking the provenance of register
// values, and relating them back to original instructions.
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
void FunctionLifter::InstrumentDataflowProvenance(llvm::BasicBlock *block) {
  if (!data_provenance_function) {
    data_provenance_function =
        semantics_module->getFunction(kAnvillDataProvenanceFunc);

    if (!data_provenance_function) {
      llvm::Type *args[] = {mem_ptr_type, pc_reg_type};
      auto fty = llvm::FunctionType::get(mem_ptr_type, args, true);
      data_provenance_function =
          llvm::Function::Create(fty, llvm::GlobalValue::ExternalLinkage,
                                 kAnvillDataProvenanceFunc, *semantics_module);
    }
  }

  std::vector<llvm::Value *> args;
  llvm::IRBuilder<> ir(block);
  args.push_back(ir.CreateLoad(mem_ptr_type, mem_ptr_ref));
  args.push_back(llvm::ConstantInt::get(pc_reg_type, curr_inst->pc));
  options.arch->ForEachRegister([&](const remill::Register *reg) {
    if (reg != pc_reg && reg != sp_reg && reg->EnclosingRegister() == reg) {
      args.push_back(
          this->op_lifter->LoadRegValue(block, state_ptr, reg->name));
    }
  });

  ir.CreateStore(ir.CreateCall(data_provenance_function, args), mem_ptr_ref);
}

// Adds a 'breakpoint' instrumentation, which calls functions that are named
// with an instruction's address just before that instruction executes. These
// are nifty to spot checking bitcode. This function is used like:
//
//      mem = breakpoint_<hexaddr>(mem, PC, NEXT_PC)
//
// That way, we can look at uses and compare the second argument to the
// hex address encoded in the function name, and also look at the third argument
// and see if it corresponds to the subsequent instruction address.
void FunctionLifter::InstrumentCallBreakpointFunction(llvm::BasicBlock *block) {
  std::stringstream ss;
  ss << "breakpoint_" << std::hex << curr_inst->pc;

  const auto func_name = ss.str();
  auto module = block->getModule();
  auto func = module->getFunction(func_name);
  if (!func) {
    llvm::Type *const params[] = {mem_ptr_type, address_type, address_type};
    const auto fty = llvm::FunctionType::get(mem_ptr_type, params, false);
    func = llvm::Function::Create(fty, llvm::GlobalValue::ExternalLinkage,
                                  func_name, module);

    // Make sure to keep this function around (along with `ExternalLinkage`).
    func->addFnAttr(llvm::Attribute::OptimizeNone);
    func->removeFnAttr(llvm::Attribute::AlwaysInline);
    func->removeFnAttr(llvm::Attribute::InlineHint);
    func->addFnAttr(llvm::Attribute::NoInline);
    func->addFnAttr(llvm::Attribute::ReadNone);

    llvm::IRBuilder<> ir(llvm::BasicBlock::Create(llvm_context, "", func));
    ir.CreateRet(remill::NthArgument(func, 0));
  }

  llvm::Value *args[] = {
      new llvm::LoadInst(mem_ptr_type, mem_ptr_ref, llvm::Twine::createNull(),
                         block),
      this->op_lifter->LoadRegValue(block, state_ptr, remill::kPCVariableName),
      this->op_lifter->LoadRegValue(block, state_ptr,
                                    remill::kNextPCVariableName)};
  llvm::IRBuilder<> ir(block);
  ir.CreateCall(func, args);
}

// Visit an instruction, and lift it into a basic block. Then, based off of
// the category of the instruction, invoke one of the category-specific
// lifters to enact a change in control-flow.
void FunctionLifter::VisitInstruction(
    remill::Instruction &inst, llvm::BasicBlock *block,
    remill::DecodingContext prev_insn_context) {
  curr_inst = &inst;

  std::optional<remill::Instruction> delayed_inst;

  if (options.track_provenance) {
    InstrumentDataflowProvenance(block);
  }

  if (options.add_breakpoints) {
    InstrumentCallBreakpointFunction(block);
  }

  // Even when something isn't supported or is invalid, we still lift
  // a call to a semantic, e.g.`INVALID_INSTRUCTION`, so we really want
  // to treat instruction lifting as an operation that can't fail.
  std::ignore = inst.GetLifter()->LiftIntoBlock(inst, block, state_ptr,
                                                false /* is_delayed */);

  // Figure out if we have to decode the subsequent instruction as a delayed
  // instruction.
  if (options.arch->MayHaveDelaySlot(inst)) {
    delayed_inst = remill::Instruction();

    if (!DecodeInstructionInto(inst.delayed_pc, true /* is_delayed */,
                               &*delayed_inst, prev_insn_context)) {
      LOG(ERROR) << "Unable to decode or use delayed instruction at "
                 << std::hex << inst.delayed_pc << std::dec << " of "
                 << inst.Serialize();
    }
  }

  // Do an initial annotation of instructions injected by `LiftIntoBlock`,
  // and prior to any lifting of a delayed instruction that might happen
  // in any of the below `Visit*` calls.
  pc_annotation = GetPCAnnotation(inst.pc);
  AnnotateInstructions(block, pc_annotation_id, pc_annotation);

  FlowVisitor visitor = {*this, inst, block, delayed_inst, prev_insn_context};
  std::visit(visitor, inst.flows);


  // Do a second pass of annotations to apply to the control-flow branching
  // instructions added in by the above `Visit*` calls.
  AnnotateInstructions(block, pc_annotation_id, pc_annotation);

  curr_inst = nullptr;
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
llvm::Value *FunctionLifter::TryCallNativeFunction(FunctionDecl decl,
                                                   llvm::Function *native_func,
                                                   llvm::BasicBlock *block) {
  llvm::IRBuilder<> irb(block);

  llvm::Value *mem_ptr = irb.CreateLoad(mem_ptr_type, mem_ptr_ref);
  mem_ptr = decl.CallFromLiftedBlock(native_func, type_specifier.Dictionary(),
                                     intrinsics, block, state_ptr, mem_ptr);
  irb.SetInsertPoint(block);
  irb.CreateStore(mem_ptr, mem_ptr_ref);
  return mem_ptr;
}

// Visit all instructions. This runs the work list and lifts instructions.
void FunctionLifter::VisitInstructions(uint64_t address) {
  remill::Instruction inst;

  // Recursively decode and lift all instructions that we come across.
  while (!edge_work_list.empty()) {
    auto [inst_addr, from_addr] = *(edge_work_list.begin());
    auto insn_context = this->decoding_contexts[{inst_addr, from_addr}];


    edge_work_list.erase(edge_work_list.begin());

    llvm::BasicBlock *const block = edge_to_dest_block[{from_addr, inst_addr}];
    CHECK_NOTNULL(block);
    if (!block->empty()) {
      continue;  // Already handled.
    }

    llvm::BasicBlock *&inst_block = addr_to_block[inst_addr];
    if (!inst_block) {
      inst_block = block;

      // We've already lifted this instruction via another control-flow edge.
    } else {
      auto br = llvm::BranchInst::Create(inst_block, block);
      AnnotateInstruction(br, pc_annotation_id, pc_annotation);
      continue;
    }

    // Decode.
    auto next_context = DecodeInstructionInto(inst_addr, false /* is_delayed */,
                                              &inst, insn_context);
    if (!next_context) {
      if (inst_addr == func_address) {
        inst.pc = inst_addr;
        inst.arch_name = options.arch->arch_name;

        // Failed to decode the first instruction of the function, but we can
        // possibly recover via a tail-call to a redirection address!
        if (inst_addr != func_address) {
          // TODO(Ian): is this context right?
          this->BranchToInst(func_address, inst_addr, insn_context, block);
          continue;
        }
      }


      // TODO(Ian): If we hit this in our new model then the low level lift is a failure and we need to mark this somehow...
      // otherwise we are inventing the abscence of control flow...
      LOG(ERROR) << "Could not decode instruction at " << std::hex << inst_addr
                 << " reachable from instruction " << from_addr
                 << " in function at " << func_address << std::dec;

      auto call =
          remill::AddTerminatingTailCall(block, intrinsics.error, intrinsics);
      AnnotateInstruction(call, pc_annotation_id, pc_annotation);
      MuteStateEscape(call);
      continue;

      // Didn't get a valid instruction.
    } else if (!inst.IsValid() || inst.IsError()) {
      auto call =
          remill::AddTerminatingTailCall(block, intrinsics.error, intrinsics);
      AnnotateInstruction(call, pc_annotation_id, pc_annotation);
      MuteStateEscape(call);
      continue;
    } else {
      VisitInstruction(inst, block, insn_context);
    }
  }
}

// Get the annotation for the program counter `pc`, or `nullptr` if we're
// not doing annotations.
llvm::MDNode *FunctionLifter::GetPCAnnotation(uint64_t pc) const {
  if (options.pc_metadata_name) {
    auto pc_val = llvm::ConstantInt::get(address_type, pc);
    auto pc_md = llvm::ValueAsMetadata::get(pc_val);
    return llvm::MDNode::get(llvm_context, pc_md);
  } else {
    return nullptr;
  }
}

// Declare the function decl `decl` and return an `llvm::Function *`.
llvm::Function *FunctionLifter::GetOrDeclareFunction(const FunctionDecl &decl) {
  const auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, llvm_context));

  // NOTE(pag): This may find declarations from prior lifts that have been
  //            left around in the semantics module.
  auto &native_func = addr_to_func[decl.address];
  if (native_func) {
    CHECK_EQ(native_func->getFunctionType(), func_type);
    return native_func;
  }

  // By default we do not want to deal with function names until the very end of
  // lifting. Instead, we assign a temporary name based on the function's
  // starting address, its type, and its calling convention.
  std::stringstream ss;
  ss << "sub_" << std::hex << decl.address << '_'
     << type_specifier.EncodeToString(func_type,
                                      EncodingFormat::kValidSymbolCharsOnly)
     << '_' << std::dec << decl.calling_convention;

  const auto base_name = ss.str();
  func_name_to_address.emplace(base_name, decl.address);

  // Try to get it as an already named function.
  native_func = semantics_module->getFunction(base_name);
  if (native_func) {
    CHECK_EQ(native_func->getFunctionType(), func_type);
    return native_func;
  }

  native_func =
      llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                             base_name, semantics_module.get());
  native_func->setCallingConv(decl.calling_convention);
  native_func->removeFnAttr(llvm::Attribute::InlineHint);
  native_func->removeFnAttr(llvm::Attribute::AlwaysInline);
  native_func->addFnAttr(llvm::Attribute::NoInline);
  if (decl.is_noreturn) {
    native_func->addFnAttr(llvm::Attribute::NoReturn);
  }
  return native_func;
}

// Allocate and initialize the state structure.
void FunctionLifter::AllocateAndInitializeStateStructure(
    llvm::BasicBlock *block, const remill::Arch *arch) {
  llvm::IRBuilder<> ir(block);
  const auto state_type = arch->StateStructType();
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
    case StateStructureInitializationProcedure::
        kGlobalRegisterVariablesAndZeroes:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::Constant::getNullValue(state_type), state_ptr);
      InitializeStateStructureFromGlobalRegisterVariables(block);
      break;
    case StateStructureInitializationProcedure::
        kGlobalRegisterVariablesAndUndef:
      state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::UndefValue::get(state_type), state_ptr);
      InitializeStateStructureFromGlobalRegisterVariables(block);
      break;
  }

  ArchSpecificStateStructureInitialization(block);
}

// Perform architecture-specific initialization of the state structure
// in `block`.
void FunctionLifter::ArchSpecificStateStructureInitialization(
    llvm::BasicBlock *block) {

  if (is_x86_or_amd64) {
    llvm::IRBuilder<> ir(block);

    const auto ssbase_reg = options.arch->RegisterByName("SSBASE");
    const auto fsbase_reg = options.arch->RegisterByName("FSBASE");
    const auto gsbase_reg = options.arch->RegisterByName("GSBASE");
    const auto dsbase_reg = options.arch->RegisterByName("DSBASE");
    const auto esbase_reg = options.arch->RegisterByName("ESBASE");
    const auto csbase_reg = options.arch->RegisterByName("CSBASE");

    if (gsbase_reg) {
      const auto gsbase_val = llvm::ConstantExpr::getPtrToInt(
          llvm::ConstantExpr::getAddrSpaceCast(
              llvm::ConstantExpr::getNullValue(
                  llvm::PointerType::get(block->getContext(), 256)),
              llvm::PointerType::get(block->getContext(), 0)),
          pc_reg_type);
      ir.CreateStore(gsbase_val, gsbase_reg->AddressOf(state_ptr, ir));
    }

    if (fsbase_reg) {
      const auto fsbase_val = llvm::ConstantExpr::getPtrToInt(
          llvm::ConstantExpr::getAddrSpaceCast(
              llvm::ConstantExpr::getNullValue(
                  llvm::PointerType::get(block->getContext(), 257)),
              llvm::PointerType::get(block->getContext(), 0)),
          pc_reg_type);
      ir.CreateStore(fsbase_val, fsbase_reg->AddressOf(state_ptr, ir));
    }

    if (ssbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     ssbase_reg->AddressOf(state_ptr, ir));
    }

    if (dsbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     dsbase_reg->AddressOf(state_ptr, ir));
    }

    if (esbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     esbase_reg->AddressOf(state_ptr, ir));
    }

    if (csbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     csbase_reg->AddressOf(state_ptr, ir));
    }
  }
}

// Initialize the state structure with default values, loaded from global
// variables. The purpose of these global variables is to show that there are
// some unmodelled external dependencies inside of a lifted function.
void FunctionLifter::InitializeStateStructureFromGlobalRegisterVariables(
    llvm::BasicBlock *block) {

  // Get or create globals for all top-level registers. The idea here is that
  // the spec could feasibly miss some dependencies, and so after optimization,
  // we'll be able to observe uses of `__anvill_reg_*` globals, and handle
  // them appropriately.

  llvm::IRBuilder<> ir(block);

  options.arch->ForEachRegister([=, &ir](const remill::Register *reg_) {
    if (auto reg = reg_->EnclosingRegister();
        reg_ == reg && reg != sp_reg && reg != pc_reg) {

      std::stringstream ss;
      ss << kUnmodelledRegisterPrefix << reg->name;
      const auto reg_name = ss.str();

      auto reg_global = semantics_module->getGlobalVariable(reg_name);
      if (!reg_global) {
        reg_global = new llvm::GlobalVariable(
            *semantics_module, reg->type, false,
            llvm::GlobalValue::ExternalLinkage, nullptr, reg_name);
      }

      const auto reg_ptr = reg->AddressOf(state_ptr, block);
      ir.CreateStore(ir.CreateLoad(reg->type, reg_global), reg_ptr);
    }
  });
}

// Set up `native_func` to be able to call `lifted_func`. This means
// marshalling high-level argument types into lower-level values to pass into
// a stack-allocated `State` structure. This also involves providing initial
// default values for registers.
void FunctionLifter::CallLiftedFunctionFromNativeFunction(
    const FunctionDecl &decl) {
  if (!native_func->isDeclaration()) {
    return;
  }

  // Create a state structure and a stack frame in the native function
  // and we'll call the lifted function with that. The lifted function
  // will get inlined into this function.
  auto block = llvm::BasicBlock::Create(llvm_context, "", native_func);

  // Create a memory pointer.
  llvm::Value *mem_ptr = llvm::Constant::getNullValue(mem_ptr_type);

  // Stack-allocate and initialize the state pointer.
  AllocateAndInitializeStateStructure(block, decl.arch);

  auto pc_ptr = pc_reg->AddressOf(state_ptr, block);
  auto sp_ptr = sp_reg->AddressOf(state_ptr, block);

  llvm::IRBuilder<> ir(block);

  // Initialize the program counter.
  auto pc = options.program_counter_init_procedure(ir, pc_reg, func_address);
  ir.CreateStore(pc, pc_ptr);

  // Initialize the stack pointer.
  ir.CreateStore(options.stack_pointer_init_procedure(ir, sp_reg, func_address),
                 sp_ptr);

  auto &types = type_specifier.Dictionary();

  // Does this function have a return address? Most functions are provided a
  // return address on the stack, however the program entrypoint (usually
  // `_start`) won't have one. When we initialize the stack frame, we should
  // take note of this flag and in the case of the program entrypoint, omit the
  // symbolic return address from the stack frame.
  if (!decl.return_address.type->isVoidTy()) {
    auto ra =
        options.return_address_init_procedure(ir, address_type, func_address);

    mem_ptr = StoreNativeValue(ra, decl.return_address, types, intrinsics,
                               block, state_ptr, mem_ptr);
  }

  // Store the function parameters either into the state struct
  // or into memory (likely the stack).
  auto arg_index = 0u;
  for (auto &arg : native_func->args()) {
    const auto &param_decl = decl.params[arg_index++];
    mem_ptr = StoreNativeValue(&arg, param_decl, types, intrinsics, block,
                               state_ptr, mem_ptr);
  }

  llvm::Value *lifted_func_args[remill::kNumBlockArgs] = {};
  lifted_func_args[remill::kStatePointerArgNum] = state_ptr;
  lifted_func_args[remill::kMemoryPointerArgNum] = mem_ptr;
  lifted_func_args[remill::kPCArgNum] = pc;
  auto call_to_lifted_func = ir.CreateCall(lifted_func->getFunctionType(),
                                           lifted_func, lifted_func_args);
  if (decl.is_noreturn) {
    call_to_lifted_func->setDoesNotReturn();
  }
  mem_ptr = call_to_lifted_func;

  // Annotate all instructions leading up to and including the call of the
  // lifted function using the function's address.
  //
  // NOTE(pag): We don't annotate any of the subsequently created instructions
  //            for marshalling return values back out because there may be
  //            multiple return/tail-call sites in the function we've just
  //            lifted.
  AnnotateInstructions(block, pc_annotation_id, GetPCAnnotation(func_address));

  llvm::Value *ret_val = nullptr;

  if (decl.returns.size() == 1) {
    ret_val = LoadLiftedValue(decl.returns.front(), types, intrinsics, block,
                              state_ptr, mem_ptr);
    ir.SetInsertPoint(block);

  } else if (1 < decl.returns.size()) {
    ret_val = llvm::UndefValue::get(native_func->getReturnType());
    auto index = 0u;
    for (auto &ret_decl : decl.returns) {
      auto partial_ret_val = LoadLiftedValue(ret_decl, types, intrinsics, block,
                                             state_ptr, mem_ptr);
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
void FunctionLifter::RecursivelyInlineLiftedFunctionIntoNativeFunction(void) {
  std::vector<llvm::CallInst *> calls_to_inline;

  CHECK(!llvm::verifyModule(*this->native_func->getParent(), &llvm::errs()));

  // Set of instructions that we should not annotate because we can't tie them
  // to a particular instruction address.
  std::unordered_set<llvm::Instruction *> insts_without_provenance;
  if (options.pc_metadata_name) {
    for (auto &inst : llvm::instructions(*native_func)) {
      if (!inst.getMetadata(pc_annotation_id)) {
        insts_without_provenance.insert(&inst);
      }
    }
  }

  for (auto changed = true; changed; changed = !calls_to_inline.empty()) {
    calls_to_inline.clear();

    for (auto &inst : llvm::instructions(*native_func)) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst); call_inst) {
        if (auto called_func = call_inst->getCalledFunction();
            called_func && !called_func->isDeclaration() &&
            !called_func->hasFnAttribute(llvm::Attribute::NoInline)) {
          calls_to_inline.push_back(call_inst);
        }
      }
    }

    for (llvm::CallInst *call_inst : calls_to_inline) {
      llvm::MDNode *call_pc = nullptr;
      if (options.pc_metadata_name) {
        call_pc = call_inst->getMetadata(pc_annotation_id);
      }

      llvm::InlineFunctionInfo info;
      auto res = llvm::InlineFunction(*call_inst, info);

      CHECK(res.isSuccess());

      // Propagate PC metadata from call sites into inlined call bodies.
      if (options.pc_metadata_name) {
        for (auto &inst : llvm::instructions(*native_func)) {
          if (!inst.getMetadata(pc_annotation_id)) {
            if (insts_without_provenance.count(&inst)) {
              continue;

              // This call site had no associated PC metadata, and so we want
              // to exclude any inlined code from accidentally being associated
              // with other PCs on future passes.
            } else if (!call_pc) {
              insts_without_provenance.insert(&inst);

              // We can propagate the annotation.
            } else {
              inst.setMetadata(pc_annotation_id, call_pc);
            }
          }
        }
      }
    }
  }

  // Initialize cleanup optimizations


  if (llvm::verifyFunction(*native_func, &llvm::errs())) {

    LOG(FATAL) << "Function verification failed: "
               << native_func->getName().str() << " "
               << remill::LLVMThingToString(native_func->getType());
  }

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
llvm::Function *FunctionLifter::DeclareFunction(const FunctionDecl &decl) {

  // This is our higher-level function, i.e. it presents itself more like
  // a function compiled from C/C++, rather than being a three-argument Remill
  // function. In this function, we will stack-allocate a `State` structure,
  // then call a `lifted_func` below, which will embed the instruction
  // semantics.
  return GetOrDeclareFunction(decl);
}

// Lift a function. Will return `nullptr` if the memory is
// not accessible or executable.
llvm::Function *FunctionLifter::LiftFunction(const FunctionDecl &decl) {
  addr_to_func.clear();
  edge_work_list.clear();
  edge_to_dest_block.clear();
  addr_to_block.clear();
  this->op_lifter->ClearCache();
  curr_decl = &decl;
  curr_inst = nullptr;
  state_ptr = nullptr;
  mem_ptr_ref = nullptr;
  func_address = decl.address;
  native_func = DeclareFunction(decl);
  pc_annotation = GetPCAnnotation(func_address);

  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      memory_provider.Query(func_address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail) ||
      !MemoryProvider::IsExecutable(first_byte_perms)) {
    LOG(ERROR) << "Address is not valid for func " << std::hex << decl.address;
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

  if (decl.lift_as_decl) {
    return native_func;
  }

  // The address is valid, the memory is executable, but we don't actually have
  // the data available for lifting, so leave us with just a declaration.
  if (!MemoryProvider::HasByte(first_byte_avail)) {
    LOG(ERROR) << "Memprov does not have bytes for func: " << std::hex
               << decl.address;
    return native_func;
  }

  // Every lifted function starts as a clone of __remill_basic_block. That
  // prototype has multiple arguments (memory pointer, state pointer, program
  // counter). This extracts the state pointer.
  lifted_func = options.arch->DefineLiftedFunction(
      native_func->getName().str() + ".lifted", semantics_module.get());

  state_ptr = remill::NthArgument(lifted_func, remill::kStatePointerArgNum);

  lifted_func->removeFnAttr(llvm::Attribute::NoInline);
  lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);
  lifted_func->setLinkage(llvm::GlobalValue::InternalLinkage);

  const auto pc = remill::NthArgument(lifted_func, remill::kPCArgNum);
  const auto entry_block = &(lifted_func->getEntryBlock());
  pc_reg_ref =
      this->op_lifter->LoadRegAddress(entry_block, state_ptr, pc_reg->name)
          .first;
  next_pc_reg_ref =
      this->op_lifter
          ->LoadRegAddress(entry_block, state_ptr, remill::kNextPCVariableName)
          .first;
  sp_reg_ref =
      this->op_lifter->LoadRegAddress(entry_block, state_ptr, sp_reg->name)
          .first;

  mem_ptr_ref = remill::LoadMemoryPointerRef(entry_block);

  // Force initialize both the `PC` and `NEXT_PC` from the `pc` argument.
  // On some architectures, `NEXT_PC` is a "pseudo-register", i.e. an `alloca`
  // inside of `__remill_basic_block`, of which `lifted_func` is a clone, and
  // so we want to ensure it gets reliably initialized before any lifted
  // instructions may depend upon it.
  llvm::IRBuilder<> ir(entry_block);
  ir.CreateStore(pc, next_pc_reg_ref);
  ir.CreateStore(pc, pc_reg_ref);

  // Add a branch between the first block of the lifted function, which sets
  // up some local variables, and the block that will contain the lifted
  // instruction.
  //
  // NOTE(pag): This also introduces the first element to the work list.
  //
  // TODO: This could be a thunk, that we are maybe lifting on purpose.
  //       How should control flow redirection behave in this case?

  // TODO(Ian): for a thumb vs arm function we need to figure out how to setup the correct initial context,
  // maybe the spec should have a section (Context reg assignments or something), where we apply those assingments to a defautl initial context

  auto default_mapping = options.arch->CreateInitialContext();
  for (const auto &[k, v] : decl.context_assignments) {
    default_mapping.UpdateContextReg(k, v);
  }

  ir.CreateBr(GetOrCreateBlock(0u, func_address, default_mapping));

  AnnotateInstructions(entry_block, pc_annotation_id,
                       GetPCAnnotation(func_address));

  DLOG(INFO) << "Visiting insns";
  // Go lift all instructions!
  VisitInstructions(func_address);

  // Fill up `native_func` with a basic block and make it call `lifted_func`.
  // This creates things like the stack-allocated `State` structure.
  CallLiftedFunctionFromNativeFunction(decl);

  // The last stage is that we need to recursively inline all calls to semantics
  // functions into `native_func`.
  RecursivelyInlineLiftedFunctionIntoNativeFunction();


  return native_func;
}

// Returns the address of a named function.
std::optional<uint64_t>
FunctionLifter::AddressOfNamedFunction(const std::string &func_name) const {
  auto it = func_name_to_address.find(func_name);
  if (it == func_name_to_address.end()) {
    return std::nullopt;
  } else {
    return it->second;
  }
}

// Lifts the machine code function starting at address `decl.address`, and
// using the architecture of the lifter context, lifts the bytes into the
// context's module.
//
// Returns an `llvm::Function *` that is part of `options_.module`.
//
// NOTE(pag): If this function returns `nullptr` then it means that we cannot
//            lift the function (e.g. bad address, or non-executable memory).
llvm::Function *EntityLifter::LiftEntity(const FunctionDecl &decl) const {
  auto &func_lifter = impl->function_lifter;
  llvm::Module *const module = impl->options.module;
  llvm::LLVMContext &context = module->getContext();
  llvm::FunctionType *module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, context));
  llvm::Function *found_by_type = nullptr;
  llvm::Function *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // function at the corresponding address.
  impl->ForEachEntityAtAddress(decl.address, [&](llvm::Constant *gv) {
    if (auto func = llvm::dyn_cast<llvm::Function>(gv)) {
      if (func->getFunctionType() == module_func_type) {
        found_by_type = func;

      } else if (!found_by_address) {
        found_by_address = func;
      }
    }
  });

  LOG_IF(ERROR, found_by_address != nullptr)
      << "Ignoring existing version of function at address " << std::hex
      << decl.address << " with type "
      << remill::LLVMThingToString(found_by_address->getFunctionType())
      << " and lifting function with type "
      << remill::LLVMThingToString(module_func_type);

  // Try to lift the function. If we failed then return the function found
  // with a matching type, if any.
  const auto func = func_lifter.LiftFunction(decl);
  if (!func) {
    return found_by_type;
  }

  // Make sure the names match up so that when we copy `func` into
  // `options.module`, we end up copying into the right function.
  std::string old_name;
  if (found_by_type && found_by_type->getName() != func->getName()) {
    old_name = found_by_type->getName().str();
    found_by_type->setName(func->getName());
  }

  // Add the function to the entity lifter's target module.
  const auto func_in_target_module =
      func_lifter.AddFunctionToContext(func, decl.address, *impl);

  // If we had a previous declaration/definition, then we want to make sure
  // that we replaced its body, and we also want to make sure that if our
  // default function naming scheme is not using the same name as the function
  // then we fixup its name to be its prior name. This could happen if the
  // user renames a function between lifts/declares.
  if (found_by_type) {
    CHECK_EQ(func_in_target_module, found_by_type);
    if (!old_name.empty() && func_in_target_module->getName() != old_name) {
      func_in_target_module->setName(old_name);
    }
  }

  return func_in_target_module;
}

// Declare the function associated with `decl` in the context's module.
//
// NOTE(pag): If this function returns `nullptr` then it means that we cannot
//            declare the function (e.g. bad address, or non-executable
//            memory).
llvm::Function *EntityLifter::DeclareEntity(const FunctionDecl &decl) const {
  auto &func_lifter = impl->function_lifter;
  llvm::Module *const module = impl->options.module;
  llvm::LLVMContext &context = module->getContext();
  llvm::FunctionType *module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, context));

  llvm::Function *found_by_type = nullptr;
  llvm::Function *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // function at the corresponding address.
  //
  // TODO(pag): Refactor out this copypasta.
  impl->ForEachEntityAtAddress(decl.address, [&](llvm::Constant *gv) {
    if (auto func = llvm::dyn_cast<llvm::Function>(gv)) {
      if (func->getFunctionType() == module_func_type) {
        found_by_type = func;

      } else if (!found_by_address) {
        found_by_address = func;
      }
    }
  });

  // We've already got a declaration for this function; return it.
  if (found_by_type) {
    return found_by_type;
  }

  LOG_IF(ERROR, found_by_address != nullptr)
      << "Ignoring existing version of function at address " << std::hex
      << decl.address << " with type "
      << remill::LLVMThingToString(found_by_address->getFunctionType())
      << " and declaring function with type "
      << remill::LLVMThingToString(module_func_type);

  if (const auto func = func_lifter.DeclareFunction(decl)) {
    DCHECK(!module->getFunction(func->getName()));
    return func_lifter.AddFunctionToContext(func, decl.address, *impl);
  } else {
    return nullptr;
  }
}

namespace {

// Erase the body of a function.
static void EraseFunctionBody(llvm::Function *func) {
  std::vector<llvm::BasicBlock *> blocks_to_erase;
  std::vector<llvm::Instruction *> insts_to_erase;

  // Collect stuff for erasure.
  for (auto &block : *func) {
    block.dropAllReferences();
  }

  while (!func->isDeclaration()) {
    func->back().eraseFromParent();
  }
}

}  // namespace

// Update the associated entity lifter with information about this
// function, and copy the function into the context's module. Returns the
// version of `func` inside the module of the lifter context.
llvm::Function *
FunctionLifter::AddFunctionToContext(llvm::Function *func, uint64_t address,
                                     EntityLifterImpl &lifter_context) const {

  const auto target_module = options.module;
  auto &module_context = target_module->getContext();
  const auto name = func->getName().str();
  const auto module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(func->getFunctionType(), module_context));

  // Try to get the old version of the function by name. If it exists and has
  // a body then erase it. As much as possible, we want to maintain referential
  // transparency w.r.t. user code, and not suddenly delete things out from
  // under them.
  auto new_version = target_module->getFunction(name);
  if (new_version) {
    CHECK_EQ(module_func_type, new_version->getFunctionType());
    if (!new_version->isDeclaration()) {
      EraseFunctionBody(new_version);
      CHECK(new_version->isDeclaration());
    }

    // It's possible that we've lifted this function before, but that it was
    // renamed by user code, and so the above check failed. Go check for that.
  } else {
    lifter_context.ForEachEntityAtAddress(address, [&](llvm::Constant *gv) {
      if (auto gv_func = llvm::dyn_cast<llvm::Function>(gv);
          gv_func && gv_func->getFunctionType() == module_func_type) {
        CHECK(!new_version);
        new_version = gv_func;
      }
    });
  }

  // This is the first time we're lifting this function, or even the first time
  // we're seeing a reference to it, so we will need to make the function in
  // the target module.
  if (!new_version) {
    new_version = llvm::Function::Create(module_func_type,
                                         llvm::GlobalValue::ExternalLinkage,
                                         name, target_module);
  }

  remill::CloneFunctionInto(func, new_version);

  // Now that we're done, erase the body of `func`. We keep `func` around
  // just in case it will be needed in future lifts.
  EraseFunctionBody(func);

  if (auto func_annotation = GetPCAnnotation(address)) {
    new_version->setMetadata(pc_annotation_id, func_annotation);
  }

  // Update the context to keep its internal concepts of what LLVM objects
  // correspond with which native binary addresses.
  lifter_context.AddEntity(new_version, address);

  // The function we just lifted may call other functions, so we need to go
  // find those and also use them to update the context.
  for (auto &inst : llvm::instructions(*new_version)) {
    if (auto call = llvm::dyn_cast<llvm::CallBase>(&inst)) {
      if (auto called_func = call->getCalledFunction()) {
        const auto called_func_name = called_func->getName().str();
        auto called_func_addr = AddressOfNamedFunction(called_func_name);
        if (called_func_addr) {
          lifter_context.AddEntity(called_func, *called_func_addr);
        }
      }
    }
  }

  return new_version;
}


void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::NormalInsn &normal) {
  this->lifter.VisitNormal(this->inst, this->block, normal);
}
void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::InvalidInsn &) {
  this->lifter.VisitInvalid(inst, block);
}


void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::ErrorInsn &) {
  this->lifter.VisitError(inst, delayed_inst, block);
}
void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::DirectJump &djump) {
  this->lifter.VisitDirectJump(inst, delayed_inst, block, djump);
}

void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::IndirectJump &ijump) {
  this->lifter.VisitIndirectJump(inst, delayed_inst, block, ijump,
                                 prev_context);
}

void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::IndirectFunctionCall &icall) {
  this->lifter.VisitIndirectFunctionCall(inst, delayed_inst, block, icall,
                                         prev_context);
}
void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::DirectFunctionCall &dcall) {
  this->lifter.VisitDirectFunctionCall(inst, delayed_inst, block, dcall,
                                       prev_context);
}
void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::FunctionReturn &) {
  this->lifter.VisitFunctionReturn(inst, delayed_inst, block);
}
void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::AsyncHyperCall &async_hcall) {
  this->lifter.VisitAsyncHyperCall(inst, delayed_inst, block);
}
void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::ConditionalInstruction &cond_insn) {
  this->lifter.VisitConditionalInstruction(inst, delayed_inst, block, cond_insn,
                                           this->prev_context);
}

void FunctionLifter::FlowVisitor::operator()(
    const remill::Instruction::NoOp &noop) {
  this->lifter.VisitNoOp(inst, block, noop);
}

}  // namespace anvill
