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

namespace anvill {

class BaseFunctionPass {
 public:
  BaseFunctionPass(void) = default;
  virtual ~BaseFunctionPass(void) = default;

  // Returns true if this instruction references the stack pointer
  static bool
  InstructionReferencesStackPointer(const llvm::DataLayout &data_layout,
                                    const llvm::Instruction &instr);

  // Returns true if this is either a store or a load instruction
  static bool IsMemoryOperation(const llvm::Instruction &instr);
};

}  // namespace anvill
