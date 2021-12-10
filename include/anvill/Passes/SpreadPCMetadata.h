/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

// Looks for instructions missing the program counter-specific metadata, and
// spreads nearby program counter-annotated metadata to those instructions.
class SpreadPCMetadata final
    : public llvm::PassInfoMixin<SpreadPCMetadata> {
 private:
  const char * const pc_metadata_name;
 public:
  inline explicit SpreadPCMetadata(const char *pc_metadata_name_)
      : pc_metadata_name(pc_metadata_name_) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static llvm::StringRef name(void);
};
}  // namespace anvill
