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

class FunctionLifter {
 private:
  const remill::Arch *arch;
  const Program &program;
  llvm::Module &module;
  llvm::LLVMContext &ctx;
  remill::IntrinsicTable intrinsics;
  remill::InstructionLifter inst_lifter;

  std::unordered_map<uint64_t, llvm::Function *> addr_to_func;
  std::unordered_map<uint64_t, llvm::BasicBlock *> addr_to_block;

  remill::Instruction DecodeInstruction(const uint64_t addr);
  llvm::Function *LiftFunction(const uint64_t addr);
  llvm::BasicBlock *GetOrCreateBlock(const uint64_t addr, llvm::Function *func);

 public:
  FunctionLifter(const remill::Arch *arch, const Program &program,
                 llvm::Module &module);

  llvm::Function *GetOrDeclareFunction(const uint64_t addr);
  bool DefineLiftedFunctions();
};

bool LiftCodeIntoModule(const remill::Arch *arch, const Program &program,
                        llvm::Module &module);

}  // namespace anvill
