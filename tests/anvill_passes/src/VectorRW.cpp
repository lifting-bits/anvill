/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Lifters.h>
#include <anvill/Passes/RewriteVectorOps.h>
#include <anvill/Providers.h>
#include <anvill/Transforms.h>
#include <doctest/doctest.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <iostream>
#include <memory>

#include "Utils.h"

namespace anvill {
static std::unique_ptr<llvm::Module>
runVectorRW(llvm::LLVMContext &llvm_context, const std::string &module_name,
            const std::string &function_name) {


  auto module = LoadTestData(llvm_context, module_name);

  auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                  remill::GetArchName("amd64"));

  REQUIRE(arch != nullptr);

  CHECK(RunFunctionPass<RewriteVectorOps>(module.get(), RewriteVectorOps()));

  for (auto &f : module->functions()) {
    for (auto &insn : llvm::instructions(f)) {
      CHECK(!llvm::isa<llvm::ShuffleVectorInst>(&insn));
    }
  }


  return module;
}


TEST_SUITE("Devectorize") {
  TEST_CASE("Devectorize Blend") {
    llvm::LLVMContext llvm_context;
    auto mod = runVectorRW(llvm_context, "VectorToRewrite.ll", "f");
    mod->dump();
  }

  TEST_CASE("Small Vec") {
    llvm::LLVMContext llvm_context;
    auto mod = runVectorRW(llvm_context, "VectorRewriteSmall.ll", "f");
    mod->dump();
  }
}


}  // namespace anvill
