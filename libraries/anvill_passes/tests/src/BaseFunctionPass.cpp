/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "BaseFunctionPass.h"

#include <doctest.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "RecoverStackFrameInformation.h"
#include "Utils.h"

namespace anvill {

TEST_SUITE("BaseFunctionPass") {
  TEST_CASE("BaseFunctionPass::SelectInstructions") {
    llvm::LLVMContext context;
    auto module = LoadTestData(context, "BaseFunctionPass.ll");
    REQUIRE(module != nullptr);

    auto function = module->getFunction("SelectInstructions");
    REQUIRE(function != nullptr);

    auto instruction_list =
        BaseFunctionPass<std::monostate>::SelectInstructions<llvm::StoreInst>(
            *function);

    CHECK(instruction_list.size() == 1U);

    instruction_list = BaseFunctionPass<std::monostate>::SelectInstructions<
        llvm::StoreInst, llvm::LoadInst>(*function);

    CHECK(instruction_list.size() == 2U);

    instruction_list = BaseFunctionPass<std::monostate>::SelectInstructions<
        llvm::BinaryOperator, llvm::LoadInst>(*function);

    CHECK(instruction_list.size() == 3U);

    instruction_list = BaseFunctionPass<std::monostate>::SelectInstructions<
        llvm::PHINode, llvm::BinaryOperator, llvm::LoadInst>(*function);

    CHECK(instruction_list.size() == 4U);
  }

  TEST_CASE("BaseFunctionPass::InstructionReferencesStackPointer") {
    llvm::LLVMContext context;
    auto module = LoadTestData(context, "BaseFunctionPass.ll");
    REQUIRE(module != nullptr);

    auto function = module->getFunction("InstructionReferencesStackPointer");
    REQUIRE(function != nullptr);

    // Attempt to run the InstructionReferencesStackPointer method on every
    // instruction

    std::size_t reference_count{};

    for (auto &instruction : llvm::instructions(*function)) {
      if (BaseFunctionPass<std::monostate>::InstructionReferencesStackPointer(
              module.get(), instruction)) {
        ++reference_count;
      }
    }

    CHECK(reference_count == 1U);
  }
}

}  // namespace anvill
