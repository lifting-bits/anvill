/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "SplitStackFrameAtReturnAddress.h"

#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "Utils.h"


namespace anvill {

TEST_SUITE("SplitStackFrameAtReturnAddress") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SplitStackFrameAtReturnAddress.ll");

    REQUIRE(module != nullptr);

    auto error_manager = ITransformationErrorManager::Create();
    CHECK(RunFunctionPass(
        module.get(), SplitStackFrameAtReturnAddress(*error_manager.get())));

    for (const auto &error : error_manager->ErrorList()) {
      CHECK_MESSAGE(false, error.description);
    }

    REQUIRE(error_manager->ErrorList().empty());
  }
}

}  // namespace anvill
