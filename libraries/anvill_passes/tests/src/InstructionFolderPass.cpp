/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "InstructionFolderPass.h"

#include <anvill/Transforms.h>
#include <doctest.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

TEST_SUITE("InstructionFolderPass") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    llvm::LLVMContext context;
    auto module = LoadTestData(context, "InstructionFolderPass.ll");

    REQUIRE(module != nullptr);

    auto arch = remill::Arch::Build(&context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));

    REQUIRE(arch != nullptr);

    auto error_manager = ITransformationErrorManager::Create();

    CHECK(RunFunctionPass(module.get(),
                          SinkSelectsAndPhis(*error_manager.get())));

    for (const auto &error : error_manager->ErrorList()) {
      CHECK_MESSAGE(false, error.description);
    }

    REQUIRE(error_manager->ErrorList().empty());
  }
}

}  // namespace anvill
