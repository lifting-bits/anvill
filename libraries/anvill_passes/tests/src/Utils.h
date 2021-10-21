/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

  fpm.addPass(function_pass);
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

}  // namespace anvill
