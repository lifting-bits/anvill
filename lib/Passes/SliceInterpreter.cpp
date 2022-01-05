/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/SliceInterpreter.h>

#include <anvill/Passes/SliceManager.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/Transforms/Utils/Cloning.h>

namespace anvill {

SliceInterpreter::~SliceInterpreter(void) {}

SliceInterpreter::SliceInterpreter(const llvm::Module &module) {
  auto builder = llvm::EngineBuilder(llvm::CloneModule(module));
  this->execEngine.reset(
      builder.setEngineKind(llvm::EngineKind::Interpreter).create());
}

llvm::GenericValue
SliceInterpreter::executeSlice(SliceID sliceId,
                               llvm::ArrayRef<llvm::GenericValue> ArgValue) {
  auto f = this->execEngine->FindFunctionNamed(
      SliceManager::getFunctionName(sliceId));

  assert(f != nullptr);
  return this->execEngine->runFunction(f, ArgValue);
}

}  // namespace anvill
