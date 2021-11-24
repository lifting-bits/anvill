/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/CrossReferenceFolder.h>
#include <anvill/Lifter.h>
#include <anvill/Lifter.h>
#include <anvill/MemoryProvider.h>
#include <anvill/TypeProvider.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Lifter.h>
#include <remill/OS/OS.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

void printFunc(const llvm::Module &mod, const std::string &name,
               const std::string &msg) {
  for (auto &f : mod) {
    if (f.hasName() && f.getName() == name) {
      std::cout << msg << std::endl;
      f.print(llvm::errs(), nullptr);
    }
  }
}
bool checkMod(const llvm::Module &mod) {

  // Verify the module
  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  auto succeeded = llvm::verifyModule(mod, &error_stream) == 0;
  error_stream.flush();

  CHECK(succeeded);
  if (!succeeded) {
    std::string error_message = "Module verification failed";
    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    std::cerr << error_message << std::endl;
  }
  return succeeded;
}
/*
class BrightenPointersFixture {
 public:
  BrightenPointersFixture(void)
      : arch(remill::Arch::Build(&llvm_context, remill::kOSLinux,
                                 remill::kArchAMD64)),
        mem(MemoryProvider::CreateNull()),
        types(TypeProvider::CreateNull(llvm_context)) {}

  llvm::LLVMContext llvm_context;
  const remill::Arch::ArchPtr arch;
  const std::shared_ptr<MemoryProvider> mem;
  const std::shared_ptr<TypeProvider> types;
};
*/
bool RunFunctionPass(llvm::Module &module) {
  llvm::FunctionPassManager pass_manager;
  pass_manager.addPass(llvm::DCEPass());

  AddBrightenPointerOperations(pass_manager, 250U);

  llvm::FunctionAnalysisManager fam;


  fam.registerPass([&] { return llvm::TargetLibraryAnalysis(); });
  fam.registerPass([&] { return llvm::PassInstrumentationAnalysis(); });

  for (auto &func : module) {
    pass_manager.run(func, fam);
  }


  return VerifyModule(&module);
}

TEST_SUITE("BrightenPointers") {

  TEST_CASE("Run the whole pass on a well-formed function") {

    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "gep_add.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }

  TEST_CASE("multiple_bitcast") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "multiple_bitcast.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }

  TEST_CASE("don't crash on loops") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "loop_test.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }

  TEST_CASE("challenge 1") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "rx_message.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));

    // mod->print(llvm::errs(), nullptr);

    CHECK(checkMod(*mod));
  }


  TEST_CASE("challenge 2") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "chall2.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));

    // mod->print(llvm::errs(), nullptr);

    CHECK(checkMod(*mod));
  }

  TEST_CASE("ret0") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "ret0.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("jmp0") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "jmp0.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_array_swap") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_array_swap_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_binja_var_none_type") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_binja_var_none_type_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    mod->print(llvm::errs(), nullptr);
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_bitops") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_bitops_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_binops") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_binops_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_cast") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_cast_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_init_list_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_init_list_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_inttoptr_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_inttoptr_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_nullptr_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_nullptr_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_ret0_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_ret0_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_struct_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_struct_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_struct_swap_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_struct_swap_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_trunc_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_trunc_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_zeroinit.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_zeroinit_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_zext_rt.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_zext_rt.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
  TEST_CASE("test_rx.ll") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "test_rx.ll");
    REQUIRE(mod != nullptr);
    CHECK(RunFunctionPass(*mod));
    CHECK(checkMod(*mod));
  }
}

};  // namespace anvill
