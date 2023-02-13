/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/SinkSelectionsIntoBranchTargets.h>
#include <anvill/Transforms.h>
#include <doctest/doctest.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/Verifier.h>

#include <ostream>

#include "Utils.h"

namespace anvill {

TEST_SUITE("SinkSelectionsIntoBranchTargets") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SinkSelectionsIntoBranchTargets.ll");

    REQUIRE(module.get() != nullptr);

    CHECK(RunFunctionPass(module.get(), SinkSelectionsIntoBranchTargets()));
  }

  TEST_CASE("SimpleCase") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SinkSelectionsIntoBranchTargets.ll");

    REQUIRE(module.get() != nullptr);

    auto function = module->getFunction("SimpleCase");
    REQUIRE(function != nullptr);

    llvm::DominatorTreeAnalysis dt;
    llvm::FunctionAnalysisManager fam;

    auto dt_res = dt.run(*function, fam);

    auto analysis =
        SinkSelectionsIntoBranchTargets::AnalyzeFunction(dt_res, *function);

    CHECK(analysis.replacement_list.size() == 2U);
    CHECK(analysis.disposable_instruction_list.size() == 1U);
  }

  TEST_CASE("MultipleSelects") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SinkSelectionsIntoBranchTargets.ll");

    REQUIRE(module.get() != nullptr);

    auto function = module->getFunction("MultipleSelects");
    REQUIRE(function != nullptr);

    llvm::DominatorTreeAnalysis dt;
    llvm::FunctionAnalysisManager fam;

    auto dt_res = dt.run(*function, fam);

    auto analysis =
        SinkSelectionsIntoBranchTargets::AnalyzeFunction(dt_res, *function);

    CHECK(analysis.replacement_list.size() == 6U);
    CHECK(analysis.disposable_instruction_list.size() == 3U);
  }

  TEST_CASE("MultipleSelectUsages") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SinkSelectionsIntoBranchTargets.ll");

    REQUIRE(module.get() != nullptr);

    auto function = module->getFunction("MultipleSelectUsages");
    REQUIRE(function != nullptr);

    llvm::DominatorTreeAnalysis dt;
    llvm::FunctionAnalysisManager fam;

    auto dt_res = dt.run(*function, fam);

    auto analysis =
        SinkSelectionsIntoBranchTargets::AnalyzeFunction(dt_res, *function);

    CHECK(analysis.replacement_list.size() == 6U);
    CHECK(analysis.disposable_instruction_list.size() == 1U);
  }
}

}  // namespace anvill
