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

#include "anvill/MCToIRLifter.h"

#include <glog/logging.h>
#include <remill/BC/Util.h>

#include <sstream>

#include "anvill/Decl.h"
#include "anvill/Program.h"
#include "anvill/Util.h"

namespace anvill {

MCToIRLifter::MCToIRLifter(const remill::Arch *_arch, const Program &_program,
                           llvm::Module &_module)
    : arch(_arch),
      program(_program),
      module(_module),
      ctx(_module.getContext()),
      intrinsics(remill::IntrinsicTable(&_module)),
      inst_lifter(remill::InstructionLifter(_arch, &intrinsics)) {}

llvm::BasicBlock *MCToIRLifter::GetOrCreateBlock(const uint64_t addr) {
  auto &block = addr_to_block[addr];
  if (block) {
    return block;
  }

  std::stringstream ss;
  ss << "inst_" << std::hex << addr;
  block = llvm::BasicBlock::Create(ctx, ss.str(), lifted_func);

  // Missed an instruction?! This can happen when IDA merges two instructions
  // into one larger synthetic instruction. This might also be a tail-call.
  work_list.emplace(addr, curr_inst ? curr_inst->pc : 0);

  return block;
}

bool MCToIRLifter::DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                                         remill::Instruction *inst_out) {
  static const auto max_inst_size = arch->MaxInstructionSize();
  inst_out->Reset();

  auto byte = program.FindByte(addr);
  if (!byte.IsExecutable()) {
    return false;
  }

  // Read the bytes.
  auto &inst_bytes = inst_out->bytes;
  inst_bytes.reserve(max_inst_size);
  for (auto i = 0u; i < max_inst_size && byte && byte.IsExecutable();
       ++i, byte = program.FindNextByte(byte)) {
    auto maybe_val = byte.Value();
    if (remill::IsError(maybe_val)) {
      LOG(ERROR) << "Unable to read value of byte at " << std::hex
                 << byte.Address() << std::dec << ": "
                 << remill::GetErrorString(maybe_val);
      break;
    } else {
      inst_bytes.push_back(static_cast<char>(remill::GetReference(maybe_val)));
    }
  }

  if (is_delayed) {
    return arch->DecodeDelayedInstruction(addr, inst_out->bytes, *inst_out);
  } else {
    return arch->DecodeInstruction(addr, inst_out->bytes, *inst_out);
  }
}

void MCToIRLifter::VisitInvalid(const remill::Instruction &inst,
                                llvm::BasicBlock *block) {
  remill::AddTerminatingTailCall(block, intrinsics.error);
}

void MCToIRLifter::VisitError(const remill::Instruction &inst,
                              remill::Instruction *delayed_inst,
                              llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.error);
}

void MCToIRLifter::VisitNormal(const remill::Instruction &inst,
                               llvm::BasicBlock *block) {
  llvm::BranchInst::Create(GetOrCreateBlock(inst.next_pc), block);
}

void MCToIRLifter::VisitNoOp(const remill::Instruction &inst,
                             llvm::BasicBlock *block) {
  VisitNormal(inst, block);
}

void MCToIRLifter::VisitDirectJump(const remill::Instruction &inst,
                                   remill::Instruction *delayed_inst,
                                   llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc), block);
}

void MCToIRLifter::VisitIndirectJump(const remill::Instruction &inst,
                                     remill::Instruction *delayed_inst,
                                     llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.jump);
}

void MCToIRLifter::VisitFunctionReturn(const remill::Instruction &inst,
                                       remill::Instruction *delayed_inst,
                                       llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  llvm::ReturnInst::Create(ctx, remill::LoadMemoryPointer(block), block);
}

// Figure out the fall-through return address for a function call. There are
// annoying SPARC-isms to deal with due to their awful ABI choices.
std::pair<uint64_t, llvm::Value *>
MCToIRLifter::LoadFunctionReturnAddress(const remill::Instruction &inst,
                                        llvm::BasicBlock *block) {

  static const bool is_sparc = arch->IsSPARC32() || arch->IsSPARC64();
  const auto pc = inst.branch_not_taken_pc;

  // The semantics for handling a call save the expected return program counter
  // into a local variable.
  auto ret_pc =
      inst_lifter.LoadRegValue(block, state_ptr, remill::kReturnPCVariableName);
  if (!is_sparc) {
    return {pc, ret_pc};
  }

  // Only bad SPARC ABI choices below this point.
  auto byte = program.FindByte(pc);

  uint8_t bytes[4] = {};

  for (auto i = 0u; i < 4u && byte; ++i, byte = program.FindNextByte(byte)) {
    auto maybe_val = byte.Value();
    if (remill::IsError(maybe_val)) {
      (void) remill::GetErrorString(maybe_val);  // Drop the error.
      return {pc, ret_pc};

    } else {
      bytes[i] = remill::GetReference(maybe_val);
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

void MCToIRLifter::VisitDirectFunctionCall(const remill::Instruction &inst,
                                           remill::Instruction *delayed_inst,
                                           llvm::BasicBlock *block) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);

  if (auto decl = program.FindFunction(inst.branch_taken_pc); decl) {
    const auto entry = GetOrDeclareFunction(*decl);
    remill::AddCall(block, entry.lifted_to_native);
  } else {
    LOG(ERROR) << "Missing declaration for function at " << std::hex
               << inst.branch_taken_pc << " called at " << inst.pc << std::dec;

    // If we do not have a function declaration, treat this as a call to an unknown address.
    remill::AddCall(block, intrinsics.function_call);
  }
  VisitAfterFunctionCall(inst, block);
}

void MCToIRLifter::VisitIndirectFunctionCall(const remill::Instruction &inst,
                                             remill::Instruction *delayed_inst,
                                             llvm::BasicBlock *block) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddCall(block, intrinsics.function_call);
  VisitAfterFunctionCall(inst, block);
}

void MCToIRLifter::VisitAfterFunctionCall(const remill::Instruction &inst,
                                          llvm::BasicBlock *block) {
  auto [ret_pc, ret_pc_val] = LoadFunctionReturnAddress(inst, block);
  auto next_pc_ptr =
      inst_lifter.LoadRegAddress(block, state_ptr, remill::kNextPCVariableName);

  llvm::IRBuilder<> ir(block);
  ir.CreateStore(ret_pc_val, next_pc_ptr, false);
  ir.CreateBr(GetOrCreateBlock(ret_pc));
}

void MCToIRLifter::VisitConditionalBranch(const remill::Instruction &inst,
                                          remill::Instruction *delayed_inst,
                                          llvm::BasicBlock *block) {

  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block = llvm::BasicBlock::Create(ctx, "", lifted_func);
  const auto not_taken_block = llvm::BasicBlock::Create(ctx, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc), taken_block);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

void MCToIRLifter::VisitAsyncHyperCall(const remill::Instruction &inst,
                                       remill::Instruction *delayed_inst,
                                       llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.async_hyper_call);
}

void MCToIRLifter::VisitConditionalAsyncHyperCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {
  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block = llvm::BasicBlock::Create(ctx, "", lifted_func);
  const auto not_taken_block = llvm::BasicBlock::Create(ctx, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);

  remill::AddTerminatingTailCall(taken_block, intrinsics.async_hyper_call);

  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

void MCToIRLifter::VisitDelayedInstruction(const remill::Instruction &inst,
                                           remill::Instruction *delayed_inst,
                                           llvm::BasicBlock *block,
                                           bool on_taken_path) {
  if (delayed_inst &&
      arch->NextInstructionIsDelayed(inst, *delayed_inst, on_taken_path)) {
    inst_lifter.LiftIntoBlock(*delayed_inst, block, state_ptr, true);
  }
}

/*
This function encodes type information within symbolic functions
so the type information can survive optimization.
it should turn some instruction like
%1 = add %4, 1
into
%1 = add %4, 1
%2 = __anvill_type_<uid>(<%4's type> %4)
%3 = ptrtoint %2 goal_type
*/
llvm::Function *MCToIRLifter::GetOrCreateTaintedFunction(
    llvm::Type *current_type, llvm::Type *goal_type, llvm::Module &mod,
    llvm::BasicBlock *curr_block, const remill::Register *reg, uint64_t pc) {
  std::stringstream func_name;
  func_name << "__anvill_type_func_" << std::hex << pc << "_" << reg->name
            << "_" << reinterpret_cast<void *>(current_type);
  llvm::Type *return_type = goal_type;

  auto anvill_type_fn_ty =
      llvm::FunctionType::get(return_type, {current_type}, false);
  mod.getOrInsertFunction(func_name.str(), anvill_type_fn_ty);
  return mod.getFunction(func_name.str());
}

void MCToIRLifter::VisitInstruction(
    remill::Instruction &inst, llvm::BasicBlock *block,
    const std::unordered_map<uint64_t, TypedRegisterDecl> &reg_map) {
  curr_inst = &inst;

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


  if (arch->MayHaveDelaySlot(inst)) {
    delayed_inst = new (&delayed_inst_storage) remill::Instruction;
    if (!DecodeInstructionInto(inst.delayed_pc, true /* is_delayed */,
                               delayed_inst)) {
      LOG(ERROR) << "Unable to decode or use delayed instruction at "
                 << std::hex << inst.delayed_pc << std::dec << " of "
                 << inst.Serialize();
    }
  }

  // Check to see if this location has type and value information associated with it
  // inst.pc
  auto match = reg_map.find(inst.pc);
  if (match != reg_map.end()) {

    // If we have information for this program point, check to see if a value exists
    const TypedRegisterDecl &decl = match->second;

    // Only operate on binaryninja pointer types for now
    if (decl.type->isPointerTy()) {

      llvm::IRBuilder irb(block);
      auto reg_pointer =
          inst_lifter.LoadRegAddress(block, state_ptr, decl.reg->name);
      llvm::Value *reg_value = irb.CreateLoad(reg_pointer);
      auto reg_type = reg_value->getType();

      if (decl.value && reg_type->isIntegerTy()) {
        reg_value = llvm::ConstantInt::get(reg_type, *decl.value);
        irb.CreateStore(reg_value, reg_pointer);
      }
      // Creates a function that returns a binja_type* and takes an argument of (reg_type)
      auto taint_func = GetOrCreateTaintedFunction(reg_type, decl.type, module,
                                                   block, decl.reg, inst.pc);
      llvm::Value *tainted_call = irb.CreateCall(taint_func, reg_value);

      // Cast the result of this call, to the goal type
      llvm::Value *replacement_reg = irb.CreatePtrToInt(tainted_call, reg_type);

      // Store the value back, this keeps the replacement_reg cast around.
      irb.CreateStore(replacement_reg, reg_pointer);
      inst_lifter.ClearCache();
    }
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

// Declare the function decl `decl` and return an `llvm::Function *`.
FunctionEntry MCToIRLifter::GetOrDeclareFunction(const FunctionDecl &decl) {
  auto &entry = addr_to_func[decl.address];
  if (entry.lifted) {
    return entry;
  }

  // By default we do not want to deal with function names until the very end of
  // lifting. Instead, lets assign a temporary name based on the function's
  // starting address.
  const auto base_name = CreateFunctionName(decl.address);

  entry.lifted_to_native =
      remill::DeclareLiftedFunction(&module, base_name + ".lifted_to_native");

  entry.lifted = remill::DeclareLiftedFunction(&module, base_name + ".lifted");

  entry.native_to_lifted = decl.DeclareInModule(base_name, module, true);
  entry.native_to_lifted->removeFnAttr(llvm::Attribute::InlineHint);
  entry.native_to_lifted->removeFnAttr(llvm::Attribute::AlwaysInline);
  entry.native_to_lifted->addFnAttr(llvm::Attribute::NoInline);
  entry.lifted->setLinkage(llvm::GlobalValue::ExternalLinkage);

  return entry;
}

FunctionEntry MCToIRLifter::LiftFunction(const FunctionDecl &decl) {
  const auto entry = GetOrDeclareFunction(decl);

  // Check if we already lifted this function. If so, do not re-lift it.
  if (!entry.native_to_lifted->isDeclaration()) {
    return entry;
  }
  // Check if there's any instruction bytes to lift
  if (auto start{program.FindByte(decl.address)};
      !start || !start.IsExecutable()) {
    return entry;
  }

  work_list.clear();
  addr_to_block.clear();

  lifted_func = entry.lifted;

  // Every lifted function starts as a clone of __remill_basic_block. That
  // prototype has multiple arguments (memory pointer, state pointer, program
  // counter). This exctracts the state pointer.
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
  llvm::BranchInst::Create(GetOrCreateBlock(decl.address),
                           &(lifted_func->getEntryBlock()));

  remill::Instruction inst;

  // Recursively decode and lift
  while (!work_list.empty()) {
    const auto ent = *(work_list.begin());
    work_list.erase(ent);
    const auto inst_addr = ent.first;
    const auto from_addr = ent.second;

    const auto block = addr_to_block[inst_addr];
    CHECK_NOTNULL(block);

    if (!block->empty()) {
      continue;  // Already handled.
    }

    // First, try to see if it's actually related to another function. This is
    // equivalent to a tail-call in the original code.
    if (auto other_decl = program.FindFunction(inst_addr);
        other_decl && inst_addr != other_decl->address) {
      const auto other_entry = GetOrDeclareFunction(decl);
      remill::AddTerminatingTailCall(block, other_entry.lifted_to_native);
      continue;
    }

    // Decode.
    if (!DecodeInstructionInto(inst_addr, false /* is_delayed */, &inst)) {
      LOG(ERROR) << "Could not decode instruction at " << std::hex << inst_addr
                 << " reachable from instruction " << from_addr
                 << " in function at " << decl.address << std::dec;
      remill::AddTerminatingTailCall(block, intrinsics.error);
      continue;

    // Didn't get a valid instruction.
    } else if (!inst.IsValid() || inst.IsError()) {
      remill::AddTerminatingTailCall(block, intrinsics.error);
      continue;

    } else {
      VisitInstruction(inst, block, decl.reg_info);
    }
  }

  return entry;
}

}  // namespace anvill
