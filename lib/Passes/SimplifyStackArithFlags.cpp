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

#include "SimplifyStackArithFlags.h"

#include <anvill/Analysis/Utils.h>
#include <anvill/BranchAnalysis.h>
namespace anvill {


llvm::PreservedAnalyses SimplifyStackArithFlags::INIT_RES =
    llvm::PreservedAnalyses::all();


bool SimplifyStackArithFlags::isTargetInstrinsic(
    const llvm::CallInst *callinsn) {
  return ParseFlagIntrinsic(callinsn).has_value();
}

llvm::PreservedAnalyses
SimplifyStackArithFlags::runOnIntrinsic(llvm::CallInst *call,
                                        llvm::FunctionAnalysisManager &am,
                                        llvm::PreservedAnalyses agg) {
  auto maybeflag = ParseFlagIntrinsic(call);
  if (maybeflag.has_value() &&
      IsRelatedToStackPointer(call->getModule(), maybeflag->over) &&
      llvm::isa<llvm::Constant>(maybeflag->over)) {
    llvm::Value *newValue = nullptr;
    if (this->constant_flags.find(maybeflag->flg) ==
        this->constant_flags.end()) {
      newValue = llvm::UndefValue::get(call->getType());
    } else {
      newValue = llvm::ConstantInt::getBool(
          call->getType(), this->constant_flags[maybeflag->flg]);
    }
    call->replaceAllUsesWith(newValue);
    call->eraseFromParent();
    agg.intersect(llvm::PreservedAnalyses::none());
  }

  return agg;
}

llvm::StringRef SimplifyStackArithFlags::name(void) {
  return "SimplifyStackArithFlags";
}


void AddSimplifyStackArithFlags(llvm::FunctionPassManager &fpm,
                                bool stack_pointer_is_signed) {
  fpm.addPass(SimplifyStackArithFlags(stack_pointer_is_signed));
}
}  // namespace anvill