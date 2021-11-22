/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/EntityLifter.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <iostream>

#include "TransformRemillJumpIntrinsics.h"
#include "Utils.h"

namespace anvill {

TEST_SUITE("TransformRemillJump_Test0") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "TransformRemillJumpData0.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(), TransformRemillJumpIntrinsics(lifter)));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");

    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_Test1") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "TransformRemillJumpData1.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(), TransformRemillJumpIntrinsics(lifter)));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_ARM32_0") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "TransformRemillJumpDataARM32_0.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("aarch32"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(), TransformRemillJumpIntrinsics(lifter)));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_ARM32_1") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "TransformRemillJumpDataARM32_1.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("aarch32"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(), TransformRemillJumpIntrinsics(lifter)));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

}  // namespace anvill
