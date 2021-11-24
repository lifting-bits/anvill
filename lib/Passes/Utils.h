/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

#include <functional>
#include <vector>

#include <anvill/Utils.h>

namespace llvm {
class CallBase;
class Function;
class Instruction;
class PointerType;
class Value;
}  // namespace llvm
namespace anvill {
namespace {

template <class... Types>
static std::vector<llvm::Instruction *> SelectInstructions(
    llvm::Function &function) {
  std::vector<llvm::Instruction *> output;

  for (auto &instruction : llvm::instructions(function)) {
    bool selected = (llvm::dyn_cast<Types>(&instruction) || ...);
    if (selected) {
      output.push_back(&instruction);
    }
  }

  return output;
}


}  // namespace

// Returns `true` if it seems like a basic block is sane.
bool BasicBlockIsSane(llvm::BasicBlock *block);

inline static bool BasicBlockIsSane(llvm::Instruction *inst) {
  return BasicBlockIsSane(inst->getParent());
}

// Find all function calls in `func` such that `pred(call)` returns `true`.
std::vector<llvm::CallBase *>
FindFunctionCalls(llvm::Function &func,
                  std::function<bool(llvm::CallBase *)> pred);

// Convert the constant `val` to have the pointer type `dest_ptr_ty`.
llvm::Value *ConvertToPointer(llvm::Instruction *usage_site,
                              llvm::Value *val_to_convert,
                              llvm::PointerType *dest_ptr_ty);

// Returns the function's IR
std::string GetFunctionIR(llvm::Function &func);

// Returns the module's IR
std::string GetModuleIR(llvm::Module &module);

llvm::PreservedAnalyses ConvertBoolToPreserved(bool);

}  // namespace anvill
