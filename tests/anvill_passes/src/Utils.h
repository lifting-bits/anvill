/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once


#include <llvm/Analysis/AssumptionCache.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/OptimizationRemarkEmitter.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>
#include <llvm/Passes/PassBuilder.h>

namespace anvill {

bool VerifyModule(llvm::Module *module);

std::unique_ptr<llvm::Module> LoadTestData(llvm::LLVMContext &context,
                                           const std::string &data_name);

template <typename PassT>
bool RunFunctionPass(llvm::Module *module, PassT &&function_pass) {

  llvm::PassBuilder pass_builder;
  llvm::FunctionPassManager fpm;
  llvm::FunctionAnalysisManager fam;
  llvm::ModuleAnalysisManager mam;
  pass_builder.registerModuleAnalyses(mam);
  pass_builder.registerFunctionAnalyses(fam);

  fam.registerPass(
      [&] { return llvm::ModuleAnalysisManagerFunctionProxy(mam); });

  fpm.addPass(std::forward<PassT>(function_pass));
  for (auto &func : *module) {
    fpm.run(func, fam);
  }

  return VerifyModule(module);
}


struct Platform final {
  std::string os;
  std::string arch;
};

using PlatformList = std::vector<Platform>;
const PlatformList &GetSupportedPlatforms(void);

std::unique_ptr<llvm::LLVMContext> CreateContext(void);

}  // namespace anvill
