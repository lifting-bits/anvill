#pragma once

#include <anvill/SliceManager.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <llvm/Transforms/Utils/Cloning.h>

namespace anvill {
class SliceID;
class SliceInterpreter {
 private:
  std::unique_ptr<llvm::ExecutionEngine> execEngine;

 public:
  SliceInterpreter() = delete;
  SliceInterpreter(const llvm::Module &module) {
    auto builder = llvm::EngineBuilder(llvm::CloneModule(module));
    this->execEngine.reset(
        builder.setEngineKind(llvm::EngineKind::Interpreter).create());
  }

  llvm::GenericValue executeSlice(SliceID sliceId,
                                  llvm::ArrayRef<llvm::GenericValue> ArgValue);
};
}  // namespace anvill