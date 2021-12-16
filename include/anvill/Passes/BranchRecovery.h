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

#include <anvill/Passes/BranchAnalysis.h>
#include <anvill/Passes/BranchHintPass.h>


namespace anvill {

// This pass consumes the analysis from BranchAnalysis and replaces the compare intrinsic
// with an icmp of the form icmp compare compared.0 compared.1 which was proven equivalent to the flag
// computation.

class BranchRecovery
    : public BranchHintPass<BranchRecovery, llvm::PreservedAnalyses>,
      llvm::PassInfoMixin<BranchRecovery> {
 public:
  // Maps CallInst to anvill_compare prims to the result
  using Result = llvm::PreservedAnalyses;

  static Result INIT_RES;


  Result runOnIntrinsic(llvm::CallInst *indirectJump,
                        llvm::FunctionAnalysisManager &am, Result agg);


  static llvm::StringRef name();
};
}  // namespace anvill