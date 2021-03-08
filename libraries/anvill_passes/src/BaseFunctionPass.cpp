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

#include <sstream>

namespace anvill {

namespace {

std::ostream &operator<<(std::ostream &stream, const SeverityType &severity) {
  switch (severity) {
    case SeverityType::Information: stream << "information"; break;
    case SeverityType::Warning: stream << "warning"; break;
    case SeverityType::Error: stream << "error"; break;
    case SeverityType::Fatal: stream << "fatal"; break;
  }

  return stream;
}

}  // namespace

BaseFunctionPass::BaseFunctionPass(ITransformationErrorManager &error_manager_)
    : error_manager(error_manager_) {}

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

void BaseFunctionPass::EmitError(
    const std::string &pass_name, SeverityType severity,
    const std::string &error_code, const std::string &message,
    const std::string &module_name,
    const std::optional<std::string> &function_name,
    const std::optional<std::string> &ir_before_pass,
    const std::optional<std::string> &ir_after_pass) {

  TransformationError error;
  error.pass_name = pass_name;
  error.severity = severity;
  error.error_code = error_code;
  error.message = message;
  error.module_name = module_name;
  error.function_name = function_name;
  error.module_before = ir_before_pass;
  error.module_after = ir_after_pass;

  std::stringstream buffer;
  buffer << "severity:" << severity << " pass_name:" << error.pass_name
         << " error_code:" << error.error_code
         << " module_name:" << error.module_name;

  if (error.function_name.has_value()) {
    buffer << " function_name:" << error.function_name.value();
  }

  buffer << " message:\"" << message << "\"";
  error.description = buffer.str();

  error_manager.Insert(std::move(error));
}

}  // namespace anvill
