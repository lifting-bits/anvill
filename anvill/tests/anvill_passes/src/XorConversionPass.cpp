/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <iostream>

#include <anvill/Passes/ConvertXorsToCmps.h>
#include "Utils.h"

namespace anvill {

  static int countXors(llvm::Function *fn) {
    int xor_count = 0;
    for (auto &inst : llvm::instructions(fn)) {
      if (auto binop = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {

        // binary op is a xor
        if (binop->getOpcode() == llvm::Instruction::Xor) {
          xor_count += 1;
        }
      }
    }
    return xor_count;
  }

  static std::tuple<int,int> runXorRemovalPassCountXors(
      const std::string &module_name, const std::string &function_name) {

    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, module_name);

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
        remill::GetArchName("amd64"));

    REQUIRE(arch != nullptr);

    int xor_count_start = countXors(module->getFunction(function_name));
    CHECK(RunFunctionPass<ConvertXorsToCmps>(module.get(), ConvertXorsToCmps()));

    const auto fn_repr = module->getFunction(function_name);
    int xor_count_end = countXors(module->getFunction(function_name));
    return {xor_count_start, xor_count_end};
  }


TEST_SUITE("XorConversion") {
  TEST_CASE("Remove Xor Flip Branch -- Not Removed (compare w/ false)") {
    auto [xor_start, xor_end] = runXorRemovalPassCountXors(
        "xor_removal_noremove.ll", "xor_removal_noremove_false");
    REQUIRE(xor_start == 1);
    REQUIRE(xor_start == xor_end);
  }

  TEST_CASE("Remove Xor Flip Branch -- Not Removed (xor not used in branch)") {
    auto [xor_start, xor_end] =  runXorRemovalPassCountXors(
        "xor_removal_noremove.ll", "xor_removal_noremove_notused");
    REQUIRE(xor_start == 1);
    REQUIRE(xor_start == xor_end);
  }

  TEST_CASE("Remove Xor Flip Branch") {
    auto [xor_start, xor_end] = runXorRemovalPassCountXors(
        "xor_removal.ll", "xor_removal");
    REQUIRE(xor_start > xor_end);
  }

  TEST_CASE("Convert a Xor used in a BranchInst and SelectInst") {
    auto [xor_start, xor_end] = runXorRemovalPassCountXors(
        "xor_conversion.ll", "xor_as_not");
    REQUIRE(xor_start > xor_end);
  }

  TEST_CASE("DO NOT convert a xor used as a branch/select") {
    auto [xor_start, xor_end] = runXorRemovalPassCountXors(
        "xor_conversion_nochange.ll", "xor_as_not_nochange");
    REQUIRE(xor_start == xor_end);
  }
}


}  // namespace anvill
