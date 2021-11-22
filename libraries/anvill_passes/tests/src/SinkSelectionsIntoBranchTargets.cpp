/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "SinkSelectionsIntoBranchTargets.h"

#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>

#include "Utils.h"

namespace anvill {

TEST_SUITE("SinkSelectionsIntoBranchTargets") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SinkSelectionsIntoBranchTargets.ll");

    REQUIRE(module != nullptr);

    auto error_manager = ITransformationErrorManager::Create();
    CHECK(RunFunctionPass(
        module.get(), SinkSelectionsIntoBranchTargets(*error_manager.get())));

    for (const auto &error : error_manager->ErrorList()) {
      CHECK_MESSAGE(false, error.description);
    }

    REQUIRE(error_manager->ErrorList().empty());
  }

  TEST_CASE("SimpleCase") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SinkSelectionsIntoBranchTargets.ll");

    REQUIRE(module != nullptr);

    auto function = module->getFunction("SimpleCase");
    REQUIRE(function != nullptr);

    auto analysis = SinkSelectionsIntoBranchTargets::AnalyzeFunction(*function);

    CHECK(analysis.replacement_list.size() == 2U);
    CHECK(analysis.disposable_instruction_list.size() == 1U);
  }

  TEST_CASE("MultipleSelects") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SinkSelectionsIntoBranchTargets.ll");

    REQUIRE(module != nullptr);

    auto function = module->getFunction("MultipleSelects");
    REQUIRE(function != nullptr);

    auto analysis = SinkSelectionsIntoBranchTargets::AnalyzeFunction(*function);

    CHECK(analysis.replacement_list.size() == 6U);
    CHECK(analysis.disposable_instruction_list.size() == 3U);
  }

  TEST_CASE("MultipleSelectUsages") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SinkSelectionsIntoBranchTargets.ll");

    REQUIRE(module != nullptr);

    auto function = module->getFunction("MultipleSelectUsages");
    REQUIRE(function != nullptr);

    auto analysis = SinkSelectionsIntoBranchTargets::AnalyzeFunction(*function);

    CHECK(analysis.replacement_list.size() == 6U);
    CHECK(analysis.disposable_instruction_list.size() == 1U);
  }
}

}  // namespace anvill
