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

#include <anvill/Analysis/Utils.h>
#include <anvill/ITransformationErrorManager.h>
#include <anvill/Result.h>
#include <llvm/IR/Instructions.h>

#include <sstream>

#include "Utils.h"

namespace anvill {

// BaseFunctionPass error codes
enum class BaseFunctionPassErrorCode {
  // The name of the requested symbolic value does not start with the
  // required `__anvill_` prefix
  InvalidSymbolicValueName,

  // A symbolic value with the same name but different
  // type already exists
  SymbolicValueConflict,
};

template <typename UserFunctionPass>
class BaseFunctionPass : public llvm::FunctionPass {
  // Function pass identifier; `&ID` needs to be unique!
  static char ID;

  // Current module
  llvm::Module *module{nullptr};

  // Module name
  std::string original_module_name;

  // Module IR, before the function pass
  std::string original_module_ir;

  // Current function name
  std::string original_function_name;

 protected:
  // Error manager, used for reporting
  ITransformationErrorManager &error_manager;

 public:
  BaseFunctionPass(ITransformationErrorManager &error_manager_);
  virtual ~BaseFunctionPass(void) = default;

  // Function pass entry point, called by LLVM
  virtual bool runOnFunction(llvm::Function &function) final override;

  // Returns true if this instruction references the stack pointer
  static bool
  InstructionReferencesStackPointer(const llvm::DataLayout &data_layout,
                                    const llvm::Instruction &instr);

  // Returns true if this is either a store or a load instruction
  static bool IsMemoryOperation(const llvm::Instruction &instr);

  // Creates or returns an existing symbolic value
  static Result<llvm::GlobalVariable *, BaseFunctionPassErrorCode>
  GetSymbolicValue(llvm::Module &module, llvm::Type *type,
                   const std::string &name);

  // Emits an error through the transformation error manager
  void EmitError(SeverityType severity, const std::string &error_code,
                 const std::string &message);
};

template <typename UserFunctionPass>
char BaseFunctionPass<UserFunctionPass>::ID = '\0';

template <typename UserFunctionPass>
BaseFunctionPass<UserFunctionPass>::BaseFunctionPass(
    ITransformationErrorManager &error_manager_)
    : llvm::FunctionPass(ID),
      error_manager(error_manager_) {}

template <typename UserFunctionPass>
bool BaseFunctionPass<UserFunctionPass>::runOnFunction(
    llvm::Function &function) {
  module = function.getParent();
  original_module_ir = GetModuleIR(*module);
  original_module_name = module->getName().str();
  original_function_name = function.getName().str();

  auto &function_pass = *static_cast<UserFunctionPass *>(this);
  return function_pass.Run(function);
}

template <typename UserFunctionPass>
bool BaseFunctionPass<UserFunctionPass>::InstructionReferencesStackPointer(
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

template <typename UserFunctionPass>
bool BaseFunctionPass<UserFunctionPass>::IsMemoryOperation(
    const llvm::Instruction &instr) {
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


template <typename UserFunctionPass>
Result<llvm::GlobalVariable *, BaseFunctionPassErrorCode>
BaseFunctionPass<UserFunctionPass>::GetSymbolicValue(llvm::Module &module,
                                                     llvm::Type *type,
                                                     const std::string &name) {

  static const std::string kMandatoryPrefix{"__anvill_"};
  if (name.find(kMandatoryPrefix) != 0U) {
    return BaseFunctionPassErrorCode::InvalidSymbolicValueName;
  }

  auto symbolic_value = module.getGlobalVariable(name);
  if (symbolic_value != nullptr) {
    if (type != symbolic_value->getType()) {
      return BaseFunctionPassErrorCode::SymbolicValueConflict;
    }

  } else {
    auto initial_value = llvm::Constant::getNullValue(type);

    symbolic_value = new llvm::GlobalVariable(
        module, type, false, llvm::GlobalValue::ExternalLinkage, initial_value,
        name);
  }

  return symbolic_value;
}

template <typename UserFunctionPass>
void BaseFunctionPass<UserFunctionPass>::EmitError(
    SeverityType severity, const std::string &error_code,
    const std::string &message) {

  TransformationError error;
  error.pass_name = getPassName().str();
  error.severity = severity;
  error.error_code = error_code;
  error.message = message;
  error.module_name = original_module_name;
  error.function_name = original_function_name;
  error.module_before = original_module_ir;

  auto current_module_ir = GetModuleIR(*module);
  if (current_module_ir != error.module_before) {
    error.module_after = current_module_ir;
  }

  std::stringstream buffer;
  buffer << "severity:";

  switch (severity) {
    case SeverityType::Information: buffer << "information"; break;
    case SeverityType::Warning: buffer << "warning"; break;
    case SeverityType::Error: buffer << "error"; break;
    case SeverityType::Fatal: buffer << "fatal"; break;
  }

  buffer << " pass_name:" << error.pass_name
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
