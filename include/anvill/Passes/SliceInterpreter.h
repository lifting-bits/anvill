/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/ADT/ArrayRef.h>
#include <llvm/ExecutionEngine/GenericValue.h>
#include <memory>

namespace llvm {
class ExecutionEngine;
class Module;
}  // namespace llvm
namespace anvill {

class SliceID;

class SliceInterpreter {
 private:
  std::unique_ptr<llvm::ExecutionEngine> execEngine;

  SliceInterpreter(void) = delete;

 public:
  ~SliceInterpreter(void);
  explicit SliceInterpreter(const llvm::Module &module);

  llvm::GenericValue executeSlice(SliceID sliceId,
                                  llvm::ArrayRef<llvm::GenericValue> ArgValue);
};

}  // namespace anvill
