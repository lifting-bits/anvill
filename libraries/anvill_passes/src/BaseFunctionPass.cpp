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

#include "BaseFunctionPass.h"

#include <anvill/Analysis/Utils.h>

namespace anvill {

bool BaseFunctionPass::InstructionReferencesStackPointer(
    const llvm::DataLayout &data_layout, const llvm::Instruction &instr) {

  auto operand_count = instr.getNumOperands();

  for (auto operand_index = 0U; operand_index < operand_count;
       ++operand_index) {

    auto operand = instr.getOperand(operand_index);
    if (IsRelatedToStackPointer(data_layout, operand)) {
      return true;
    }
  }

  return false;
}

bool BaseFunctionPass::IsMemoryOperation(const llvm::Instruction &instr) {
  if (auto load_inst = llvm::dyn_cast<llvm::LoadInst>(&instr);
      load_inst != nullptr) {
    return true;
  }

  if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(&instr);
      store_inst != nullptr) {
    return true;
  }

  return false;
}

}  // namespace anvill
