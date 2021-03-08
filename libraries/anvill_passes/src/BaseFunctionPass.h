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

#include <anvill/ITransformationErrorManager.h>
#include <llvm/IR/Instructions.h>

namespace anvill {

class BaseFunctionPass {
 protected:
  ITransformationErrorManager &error_manager;

 public:
  BaseFunctionPass(ITransformationErrorManager &error_manager_);
  virtual ~BaseFunctionPass(void) = default;

  // Returns true if this instruction references the stack pointer
  static bool
  InstructionReferencesStackPointer(const llvm::DataLayout &data_layout,
                                    const llvm::Instruction &instr);

  // Returns true if this is either a store or a load instruction
  static bool IsMemoryOperation(const llvm::Instruction &instr);

  // Emits an error through the transformation error manager
  void EmitError(const std::string &pass_name, SeverityType severity,
                 const std::string &error_code, const std::string &message,
                 const std::string &module_name,

                 const std::optional<std::string> &function_name =
                     std::optional<std::string>(),

                 const std::optional<std::string> &ir_before_pass =
                     std::optional<std::string>(),

                 const std::optional<std::string> &ir_after_pass =
                     std::optional<std::string>());
};

}  // namespace anvill
