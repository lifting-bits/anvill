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

// Looks for the following patterns that can be converted into casts, where
// we focus on high-level casting patterns, i.e. truncations, zero-extensions,
// and sign-extensions.
//
//      and i64 %val, 0xff          -> %down_casted_val = trunc %val to i8
//                                     %new_val = zext %down_casted_val to i64
//      and i64 %val, 0xffff        -> %down_casted_val = trunc %val to i16
//                                     %new_val = zext %down_casted_val to i64
//      and i64 %val, 0xffffffff    -> %down_casted_val = trunc %val to i32
//                                     %new_val = zext %down_casted_val to i64
//
// We also look for patterns of the form:
//
//      %low_val = shl i64 %val, 32
//      %signed_val = ashr i64 %low_val, 32
//
// And convert it into:
//
//      %low_val = trunc i64 %val to i32
//      %signed_val = sext i32 %low_val to i64
//
// In general, these types of patterns are easier to lift into a combination
// of one down cast, followed by one implicit upcast in decompiled code, and
// thus look simpler than the shifting/masking variants.
//
// In the latter case with shifting/masking, this type of 32-bit shifting/
// masking pattern can negatively affect offset/displacement analysis, e.g.
// for PC- and SP-relative displacements. For example:
//
//        %255 = sub i64 %252, zext (i32 ... @__anvill_sp ... to i64)
//        %256 = shl i64 %255, 32
//        %257 = ashr exact i64 %256, 32, !pc !70
class ConvertMasksToCasts final : llvm::PassInfoMixin<ConvertMasksToCasts> {
 public:
  ConvertMasksToCasts(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);

  static llvm::StringRef name(void);
};
}  // namespace anvill
