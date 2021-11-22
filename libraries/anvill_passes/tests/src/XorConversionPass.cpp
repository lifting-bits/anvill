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
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <iostream>

#include "ConvertXorToCmp.h"
#include "Utils.h"

namespace anvill {

TEST_SUITE("XorConversion") {
  TEST_CASE("Convert a Xor used in a BranchInst and SelectInst") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "xor_conversion.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass<ConvertXorToCmp>(module.get(), ConvertXorToCmp()));

    const auto xor_as_not = module->getFunction("xor_as_not");
    int xor_count = 0;
    for (auto &inst : llvm::instructions(xor_as_not)) {
      if (auto binop = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {

        // binary op is a xor
        if (binop->getOpcode() == llvm::Instruction::Xor) {
          xor_count += 1;
        }
      }
    }

    REQUIRE(xor_as_not);
    REQUIRE(xor_count == 0);
  }

  TEST_CASE("DO NOT convert a xor used as a branch/select") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "xor_conversion_nochange.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(), ConvertXorToCmp()));

    const auto xor_as_not_nochange = module->getFunction("xor_as_not_nochange");
    int xor_count = 0;
    for (auto &inst : llvm::instructions(xor_as_not_nochange)) {
      if (auto binop = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {

        // binary op is a xor
        if (binop->getOpcode() == llvm::Instruction::Xor) {
          xor_count += 1;
        }
      }
    }

    REQUIRE(xor_as_not_nochange);
    REQUIRE(xor_count == 1);
  }
}


}  // namespace anvill
