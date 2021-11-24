/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/ABI.h>
#include <anvill/Analysis/Utils.h>
#include <anvill/Passes/ITransformationErrorManager.h>
#include <anvill/Result.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>

#include <sstream>
#include <unordered_set>

#include "Utils.h"

#define ANVILL_RECORD_FUNCTION_IR 0

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
class BaseFunctionPass : public llvm::PassInfoMixin<UserFunctionPass> {


  // Current module.
  llvm::Module *module{nullptr};

  // Current function.
  llvm::Function *function{nullptr};

  // Module name
  std::string original_module_name;
#if ANVILL_RECORD_FUNCTION_IR
  // Module IR, before the function pass
  std::string original_function_ir;
#endif
  // Current function name
  std::string original_function_name;

 protected:
  // Error manager, used for reporting
  ITransformationErrorManager &error_manager;

 public:
  BaseFunctionPass(ITransformationErrorManager &error_manager_);
  virtual ~BaseFunctionPass(void) = default;


  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &fam);

  // Returns true if this instruction references the stack pointer
  static bool InstructionReferencesStackPointer(llvm::Module *module,
                                                const llvm::Instruction &instr);

  // Converts the given enum value to string
  template <typename ErrorCodeEnum>
  static std::string EnumValueToString(ErrorCodeEnum error_code);

  // Emits an error through the transformation error manager
  template <typename ErrorCodeEnum>
  void EmitError(SeverityType severity, ErrorCodeEnum error_code,
                 const std::string &message,
                 llvm::Instruction *instr = nullptr);



  // A list of llvm::User pointers
  using UserList = std::vector<llvm::User *>;

  // Returns a list of the instructions matching the given types
  template <class... Types>
  static InstructionList SelectInstructions(llvm::Function &function);

  // Tracks down all the direct and indirect users of source_instr that are
  // of the requested type
  template <class... Types>
  static UserList TrackUsersOf(llvm::User *initial_user);

  // Compatibility method for LLVM < 12
  static llvm::StructType *getTypeByName(const llvm::Module &module,
                                         llvm::StringRef name);
};

template <typename UserFunctionPass>
BaseFunctionPass<UserFunctionPass>::BaseFunctionPass(
    ITransformationErrorManager &error_manager_)
    : error_manager(error_manager_) {}

template <typename UserFunctionPass>
llvm::PreservedAnalyses
BaseFunctionPass<UserFunctionPass>::run(llvm::Function &function_,
                                        llvm::FunctionAnalysisManager &fam) {
  function = &function_;
  module = function->getParent();
#if ANVILL_RECORD_FUNCTION_IR
  original_function_ir = GetFunctionIR(*function);
#endif
  original_module_name = module->getName().str();
  original_function_name = function->getName().str();

  auto &function_pass = *static_cast<UserFunctionPass *>(this);
  return ConvertBoolToPreserved(function_pass.Run(*function, fam));
}

template <typename UserFunctionPass>
bool BaseFunctionPass<UserFunctionPass>::InstructionReferencesStackPointer(
    llvm::Module *module, const llvm::Instruction &instr) {

  auto operand_count = instr.getNumOperands();

  for (auto operand_index = 0U; operand_index < operand_count;
       ++operand_index) {

    auto operand = instr.getOperand(operand_index);
    if (IsRelatedToStackPointer(module, operand)) {
      return true;
    }
  }

  return false;
}

template <typename UserFunctionPass>
template <typename ErrorCodeEnum>
std::string BaseFunctionPass<UserFunctionPass>::EnumValueToString(
    ErrorCodeEnum error_code) {
  return "";  // TODO(pag): Replace me.
}

template <typename UserFunctionPass>
template <typename ErrorCodeEnum>
void BaseFunctionPass<UserFunctionPass>::EmitError(SeverityType severity,
                                                   ErrorCodeEnum error_code,
                                                   const std::string &message,
                                                   llvm::Instruction *instr) {

  TransformationError error;
  error.pass_name = llvm::PassInfoMixin<UserFunctionPass>::name().str();
  error.severity = severity;
  error.error_code = EnumValueToString(error_code);
  error.message = message;
  error.module_name = original_module_name;
  error.function_name = original_function_name;

#if ANVILL_RECORD_FUNCTION_IR
  error.func_before = original_function_ir;
  auto current_func_ir = GetFunctionIR(*function);
  if (current_func_ir != error.func_before) {
    error.func_after = current_func_ir;
  }
#endif

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

  if (instr != nullptr) {
    buffer << " instruction:" << remill::LLVMThingToString(instr);
  }

  buffer << " message:\"" << message << "\"";
  error.description = buffer.str();

  error_manager.Insert(std::move(error));
}

template <typename UserFunctionPass>
template <class... Types>
typename BaseFunctionPass<UserFunctionPass>::UserList
BaseFunctionPass<UserFunctionPass>::TrackUsersOf(llvm::User *initial_user) {
  std::vector<llvm::User *> pending_queue{initial_user};
  std::vector<llvm::User *> user_list;
  std::unordered_set<llvm::User *> visited;

  do {
    auto queue = std::move(pending_queue);
    pending_queue.clear();

    for (auto &instr : queue) {
      for (auto &use : instr->uses()) {
        auto user = use.getUser();
        if (visited.count(user) > 0U) {
          continue;
        }

        visited.insert(user);

        bool selected = (llvm::dyn_cast<Types>(user) || ...);
        if (selected) {
          user_list.push_back(llvm::dyn_cast<llvm::User>(user));
        } else {
          pending_queue.push_back(user);
        }
      }
    }
  } while (!pending_queue.empty());

  return user_list;
}

template <typename UserFunctionPass>
llvm::StructType *
BaseFunctionPass<UserFunctionPass>::getTypeByName(const llvm::Module &module,
                                                  llvm::StringRef name) {
#if LLVM_VERSION_MAJOR >= 12
  auto &context = module.getContext();
  return llvm::StructType::getTypeByName(context, name);

#else
  return module.getTypeByName(name);
#endif
}

}  // namespace anvill
