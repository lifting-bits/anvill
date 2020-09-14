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
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/BC/Util.h>

#include <set>

#include "anvill/Decl.h"
#include "anvill/Program.h"

namespace {

std::string CreateFunctionName(uint64_t addr) {
  std::stringstream ss;
  ss << "sub_" << std::hex << addr;
  return ss.str();
}

}  // namespace

namespace anvill {

MCToIRLifter::MCToIRLifter(const remill::Arch *_arch,
                               const Program &_program, llvm::Module &_module)
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
  ss << "inst_" << std::hex << addr << std::dec;
  block = llvm::BasicBlock::Create(ctx, ss.str());

  return block;
}

remill::Instruction *MCToIRLifter::DecodeInstruction(const uint64_t addr) {
  auto &inst = addr_to_inst[addr];
  if (inst.IsValid()) {
    return &inst;
  }
  // Read
  auto bytes = program.FindBytes(addr, arch->MaxInstructionSize());
  CHECK(bytes) << "Failed reading instruction at address: " << std::hex << addr
               << std::dec;
  // Decode
  CHECK(arch->DecodeInstruction(addr, bytes.ToString(), inst))
      << "Failed decoding instruction at address: " << std::hex << addr
      << std::dec;

  return &inst;
}

llvm::BasicBlock *MCToIRLifter::LiftInstruction(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  if (!block->empty()) {
    return block;
  }

  switch (inst_lifter.LiftIntoBlock(*inst, block)) {
    case remill::kLiftedInvalidInstruction:
      LOG(FATAL) << "Invalid instruction: " << inst->Serialize();
      break;

    case remill::kLiftedUnsupportedInstruction:
      LOG(FATAL) << "Unsupported instruction: " << inst->Serialize();
      break;

    default: break;
  }

  return block;
}

void MCToIRLifter::VisitInvalid(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  CHECK(!block->empty());
  remill::AddTerminatingTailCall(block, intrinsics.error);
}

void MCToIRLifter::VisitError(remill::Instruction *inst) {
  VisitInvalid(inst);
}

void MCToIRLifter::VisitNormal(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  CHECK(!block->empty());
  llvm::BranchInst::Create(GetOrCreateBlock(inst->next_pc), block);
}

void MCToIRLifter::VisitNoOp(remill::Instruction *inst) {
  VisitNormal(inst);
}

void MCToIRLifter::VisitDirectJump(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  CHECK(!block->empty());
  auto target = inst->branch_taken_pc;
  if (addr_to_func.count(target)) {
    // Tail calls
    remill::AddTerminatingTailCall(block, GetOrDeclareFunction(target));
  } else {
    // Regular jumps
    llvm::BranchInst::Create(GetOrCreateBlock(target), block);
  }
}

void MCToIRLifter::VisitIndirectJump(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  CHECK(!block->empty());
  remill::AddTerminatingTailCall(block, intrinsics.jump);
}

void MCToIRLifter::VisitFunctionReturn(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  CHECK(!block->empty());
  llvm::ReturnInst::Create(ctx, remill::LoadMemoryPointer(block), block);
}

void MCToIRLifter::VisitDirectFunctionCall(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  CHECK(!block->empty());
  remill::AddCall(block, GetOrDeclareFunction(inst->branch_taken_pc));
  llvm::BranchInst::Create(GetOrCreateBlock(inst->next_pc), block);
}

void MCToIRLifter::VisitIndirectFunctionCall(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  CHECK(!block->empty());
  remill::AddCall(block, intrinsics.function_call);
  llvm::ReturnInst::Create(ctx, remill::LoadMemoryPointer(block), block);
}

void MCToIRLifter::VisitConditionalBranch(remill::Instruction *inst) {
  auto block = GetOrCreateBlock(inst->pc);
  CHECK(!block->empty());
  auto if_true = GetOrCreateBlock(inst->branch_taken_pc);
  auto if_false = GetOrCreateBlock(inst->branch_not_taken_pc);
  auto cond = remill::LoadBranchTaken(block);
  llvm::BranchInst::Create(if_true, if_false, cond, block);
}

void MCToIRLifter::VisitInstruction(remill::Instruction *inst) {
  switch (inst->category) {
    case remill::Instruction::kCategoryInvalid: VisitInvalid(inst); break;
    case remill::Instruction::kCategoryError: VisitError(inst); break;
    case remill::Instruction::kCategoryNormal: VisitNormal(inst); break;
    case remill::Instruction::kCategoryNoOp: VisitNoOp(inst); break;
    case remill::Instruction::kCategoryDirectJump: VisitDirectJump(inst); break;
    case remill::Instruction::kCategoryIndirectJump:
      VisitIndirectJump(inst);
      break;
    case remill::Instruction::kCategoryFunctionReturn:
      VisitFunctionReturn(inst);
      break;
    case remill::Instruction::kCategoryDirectFunctionCall:
      VisitDirectFunctionCall(inst);
      break;
    case remill::Instruction::kCategoryIndirectFunctionCall:
      VisitIndirectFunctionCall(inst);
      break;
    case remill::Instruction::kCategoryConditionalBranch:
      VisitConditionalBranch(inst);
      break;
    case remill::Instruction::kCategoryAsyncHyperCall:
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      LOG(FATAL) << "Unimplemented handlers";
      break;
  }
}

llvm::Function *MCToIRLifter::LiftFunction(const uint64_t func_addr) {
  CHECK(addr_to_func.count(func_addr)) << "No declared function at address "
                                       << std::hex << func_addr << std::dec;
  auto &func = addr_to_func[func_addr];
  CHECK(func->empty()) << "Function " << func->getName().str()
                       << " is already lifted";
  // Get `__remill_basic_block` into `func`
  remill::CloneBlockFunctionInto(func);
  llvm::BranchInst::Create(GetOrCreateBlock(func_addr), &func->getEntryBlock());
  // Recursively decode and lift
  std::set<uint64_t> worklist({func_addr});
  while (!worklist.empty()) {
    auto inst_addr = *worklist.begin();
    worklist.erase(inst_addr);
    // Check if we already lifted `inst_addr`
    auto block = GetOrCreateBlock(inst_addr);
    if (!block->empty()) {
      continue;
    }
    // Insert `block` into `func`
    block->insertInto(func);
    // Decode
    auto inst = DecodeInstruction(inst_addr);
    // Lift into `block`
    LiftInstruction(inst);
    // Add terminators to `block`
    VisitInstruction(inst);
    // Add successors of `inst` to the worklist
    switch (inst->category) {
      default: break;
      case remill::Instruction::kCategoryNormal:
      case remill::Instruction::kCategoryNoOp:
      case remill::Instruction::kCategoryDirectFunctionCall:
        worklist.insert(inst->next_pc);
        break;

      case remill::Instruction::kCategoryDirectJump: {
        // Ignore tail calls
        auto target = inst->branch_taken_pc;
        if (!addr_to_func.count(target)) {
          worklist.insert(target);
        }
      } break;

      case remill::Instruction::kCategoryConditionalBranch:
        worklist.insert(inst->branch_taken_pc);
        worklist.insert(inst->branch_not_taken_pc);
        break;
    }
  }

  return func;
}

llvm::Function *MCToIRLifter::GetOrDeclareFunction(const uint64_t addr) {
  auto &func = addr_to_func[addr];
  if (func) {
    return func;
  }
  // Declare lifted function
  auto name = CreateFunctionName(addr) + ".lifted";
  func = remill::DeclareLiftedFunction(&module, name);
  return func;
}

llvm::Function *MCToIRLifter::GetOrDefineFunction(const uint64_t addr) {
  auto &func = addr_to_func[addr];
  if (func && !func->empty()) {
    LOG(WARNING) << "Asking to re-lift function: " << func->getName().str()
                 << "; returning current function instead";
    return func;
  }
  // Lift
  func = LiftFunction(addr);
  return func;
}

}  // namespace anvill
