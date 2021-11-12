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
#include <anvill/BranchAnalysis.h>
#include <anvill/IntrinsicPass.h>

#include <map>
namespace anvill {

// This pass attempts to remove flag computations over the stack variable, hinted by "__remill_flag_computation_*".
// The pass checks for arithmetic flags that should be constant for a constant arithmetic expression over a stack variable.
// The sign flag is configurable in the lifter options to support non user mode code.
class SimplifyStackArithFlags
    : public IntrinsicPass<SimplifyStackArithFlags, llvm::PreservedAnalyses>,
      llvm::PassInfoMixin<SimplifyStackArithFlags> {


 private:
  // Flags that can be treated as a constant boolean
  std::map<ArithFlags, bool> constant_flags = {{ArithFlags::OF, false},
                                               {ArithFlags::ZF, false},
                                               {ArithFlags::SIGN, true}};

 public:
  SimplifyStackArithFlags(bool stack_pointer_is_signed) {
    this->constant_flags.insert({ArithFlags::SIGN, stack_pointer_is_signed});
  }

  llvm::PreservedAnalyses runOnIntrinsic(llvm::CallInst *indirectJump,
                                         llvm::FunctionAnalysisManager &am,
                                         llvm::PreservedAnalyses);


  static llvm::PreservedAnalyses INIT_RES;


  bool isTargetInstrinsic(const llvm::CallInst *callinsn);
  static llvm::StringRef name();
};

}  // namespace anvill