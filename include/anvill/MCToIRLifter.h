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

#pragma once

#include <remill/Arch/Instruction.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>

#include <unordered_map>

namespace llvm {
class BasicBlock;
class Function;
class Module;
class LLVMContext;
}  // namespace llvm

namespace remill {
class Arch;
}  // namespace remill

namespace anvill {

class Program;

class MCToIRLifter {
 private:
  const remill::Arch *arch;
  const Program &program;
  llvm::Module &module;
  llvm::LLVMContext &ctx;
  remill::IntrinsicTable intrinsics;
  remill::InstructionLifter inst_lifter;
  // Result maps
  std::unordered_map<uint64_t, remill::Instruction> addr_to_inst;
  std::unordered_map<uint64_t, llvm::BasicBlock *> addr_to_block;
  std::unordered_map<uint64_t, llvm::Function *> addr_to_func;
  // Helper
  llvm::BasicBlock *GetOrCreateBlock(const uint64_t addr);
  // Visitors used to add terminators to instruction basic blocks
  void VisitInvalid(remill::Instruction *inst);
  void VisitError(remill::Instruction *inst);
  void VisitNormal(remill::Instruction *inst);
  void VisitNoOp(remill::Instruction *inst);
  void VisitDirectJump(remill::Instruction *inst);
  void VisitIndirectJump(remill::Instruction *inst);
  void VisitFunctionReturn(remill::Instruction *inst);
  void VisitDirectFunctionCall(remill::Instruction *inst);
  void VisitIndirectFunctionCall(remill::Instruction *inst);
  void VisitConditionalBranch(remill::Instruction *inst);
  void VisitInstruction(remill::Instruction *inst);
  remill::Instruction *DecodeInstruction(const uint64_t addr);
  llvm::BasicBlock *LiftInstruction(remill::Instruction *inst);
  llvm::Function *LiftFunction(const uint64_t addr);

 public:
  MCToIRLifter(const remill::Arch *arch, const Program &program,
                 llvm::Module &module);

  llvm::Function *GetOrDeclareFunction(const uint64_t addr);
  llvm::Function *GetOrDefineFunction(const uint64_t addr);
};

}  // namespace anvill
