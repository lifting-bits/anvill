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

char BaseFunctionPass::ID = '\0';

bool BaseFunctionPass::OperandReferencesStackPointer(const llvm::Value *value) {
  if (IsStackPointer(const_cast<llvm::Value *>(value))) {
    return true;
  }

  std::vector<const llvm::Value *> operand_list;

  if (auto instr = llvm::dyn_cast<llvm::Instruction>(value); instr != nullptr) {

    auto operand_count = instr->getNumOperands();
    for (auto i = 0U; i < operand_count; ++i) {
      operand_list.push_back(instr->getOperand(i));
    }

  } else if (auto constant_expr = llvm::dyn_cast<llvm::ConstantExpr>(value);
             constant_expr != nullptr) {

    auto operand_count = constant_expr->getNumOperands();
    for (auto i = 0U; i < operand_count; ++i) {
      operand_list.push_back(constant_expr->getOperand(i));
    }
  }

  for (const auto &operand : operand_list) {
    if (OperandReferencesStackPointer(operand)) {
      return true;
    }
  }

  return false;
}

bool BaseFunctionPass::InstructionReferencesStackPointer(
    const llvm::Instruction &instr) {
  auto operand_count = instr.getNumOperands();

  for (auto operand_index = 0U; operand_index < operand_count;
       ++operand_index) {

    auto operand = instr.getOperand(operand_index);
    if (OperandReferencesStackPointer(operand)) {
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
