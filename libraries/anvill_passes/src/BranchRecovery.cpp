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


#include "BranchRecovery.h"

#include <llvm/Transforms/Utils/BasicBlockUtils.h>

namespace anvill {

void AddBranchRecovery(llvm::FunctionPassManager &fpm) {
  fpm.addPass(BranchRecovery());
}

BranchRecovery::Result BranchRecovery::INIT_RES =
    llvm::PreservedAnalyses::all();

llvm::StringRef BranchRecovery::name() {
  return "BranchRecovery";
}

BranchRecovery::Result
BranchRecovery::runOnIntrinsic(llvm::CallInst *brcond,
                               llvm::FunctionAnalysisManager &am, Result agg) {
  auto res = am.getResult<BranchAnalysis>(*brcond->getFunction());
  auto brres = res.find(brcond);
  if (brres != res.end()) {
    auto ba = brres->second;
    llvm::ReplaceInstWithInst(
        brcond,
        new llvm::ICmpInst(ba.compare, ba.compared.first, ba.compared.second));

    agg.intersect(llvm::PreservedAnalyses::none());
  }

  return agg;
}
}  // namespace anvill