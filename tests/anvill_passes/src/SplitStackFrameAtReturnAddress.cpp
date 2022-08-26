/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/SplitStackFrameAtReturnAddress.h>
#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <doctest/doctest.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "Utils.h"


namespace anvill {

TEST_SUITE("SplitStackFrameAtReturnAddress") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    auto llvm_context = anvill::CreateContextWithOpaquePointers();
    auto module =
        LoadTestData(*llvm_context, "SplitStackFrameAtReturnAddress.ll");

    REQUIRE(module != nullptr);
    StackFrameRecoveryOptions opt;
    CHECK(RunFunctionPass(
        module.get(), SplitStackFrameAtReturnAddress(opt)));

  }
}

}  // namespace anvill
