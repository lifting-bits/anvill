/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include "Result.h"

namespace anvill {

class BaseFunctionPass : public llvm::FunctionPass {
  static char ID;

 public:
  BaseFunctionPass(void) : llvm::FunctionPass(ID) {}
  virtual ~BaseFunctionPass(void) override = default;

  // Returns true if this operand references the stack pointer
  static bool OperandReferencesStackPointer(const llvm::Value *value);

  // Returns true if this instruction references the stack pointer
  static bool InstructionReferencesStackPointer(const llvm::Instruction &instr);

  // Returns true if this is either a store or a load instruction
  static bool IsMemoryOperation(const llvm::Instruction &instr);
};

}  // namespace anvill
