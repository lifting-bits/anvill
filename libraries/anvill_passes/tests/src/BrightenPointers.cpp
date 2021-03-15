#include <anvill/Analysis/CrossReferenceResolver.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "BaseScenario.h"
#include "Utils.h"

namespace anvill {

TEST_SUITE("BrightenPointers") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    llvm::LLVMContext llvm_context;

    auto mod = LoadTestData(llvm_context, "gep_add.ll");

    anvill::CrossReferenceResolver resolver(mod->getDataLayout());

    auto module = RunFunctionPass(llvm_context, "gep_add.ll",
                                  CreateBrightenPointerOperations(resolver));

    // Verify the module
    std::string error_buffer;
    llvm::raw_string_ostream error_stream(error_buffer);

    auto succeeded = llvm::verifyModule(*module.get(), &error_stream) == 0;
    error_stream.flush();

    module->print(llvm::errs(), nullptr);

    CHECK(succeeded);
    if (!succeeded) {
      std::string error_message = "Module verification failed";
      if (!error_buffer.empty()) {
        error_message += ": " + error_buffer;
      }

      std::cerr << error_message << std::endl;
    }
  }
  TEST_CASE("multiple_bitcast") {
    llvm::LLVMContext llvm_context;

    auto mod = LoadTestData(llvm_context, "multiple_bitcast.ll");

    anvill::CrossReferenceResolver resolver(mod->getDataLayout());

    auto module = RunFunctionPass(llvm_context, "multiple_bitcast.ll",
                                  CreateBrightenPointerOperations(resolver));

    // Verify the module
    std::string error_buffer;
    llvm::raw_string_ostream error_stream(error_buffer);

    auto succeeded = llvm::verifyModule(*module.get(), &error_stream) == 0;
    error_stream.flush();

    for (auto &func : *mod) {
      if (func.getName() == "valid_test") {
        std::cout << "====================BEFORE===================="
                  << std::endl;
        func.print(llvm::errs(), nullptr);
      }
    }

    for (auto &func : *module) {
      if (func.getName() == "valid_test") {
        std::cout << "====================AFTER===================="
                  << std::endl;
        func.print(llvm::errs(), nullptr);
      }
    }

    for (auto &func : *mod) {
      if (func.getName() == "main") {
        std::cout << "====================BEFORE===================="
                  << std::endl;
        func.print(llvm::errs(), nullptr);
      }
    }

    for (auto &func : *module) {
      if (func.getName() == "main") {
        std::cout << "====================AFTER===================="
                  << std::endl;
        func.print(llvm::errs(), nullptr);
      }
    }


    CHECK(succeeded);
    if (!succeeded) {
      std::string error_message = "Module verification failed";
      if (!error_buffer.empty()) {
        error_message += ": " + error_buffer;
      }

      std::cerr << error_message << std::endl;
    }
  }
}

};  // namespace anvill
