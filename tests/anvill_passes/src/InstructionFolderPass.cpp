/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/HoistUsersOfSelectsAndPhis.h>

#include <anvill/Arch.h>
#include <anvill/Transforms.h>
#include <doctest.h>
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

    auto arch = BuildArch(context, remill::ArchName::kArchAMD64,
                          remill::OSName::kOSLinux);

    REQUIRE(arch != nullptr);

    CHECK(RunFunctionPass(module.get(),
                          HoistUsersOfSelectsAndPhis()));


  }
}

}  // namespace anvill
