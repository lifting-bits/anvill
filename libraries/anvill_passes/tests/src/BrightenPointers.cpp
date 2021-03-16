/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Lifters/Options.h>
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "BaseScenario.h"
#include "Utils.h"

namespace anvill {

class BrightenPointersFixture {
 public:
  BrightenPointersFixture(void)
      : arch(remill::Arch::Build(&llvm_context, remill::kOSLinux,
                                 remill::kArchAMD64)),
        mem(MemoryProvider::CreateNullMemoryProvider()),
        types(TypeProvider::CreateNullTypeProvider(llvm_context)) {}

  llvm::LLVMContext llvm_context;
  const remill::Arch::ArchPtr arch;
  const std::shared_ptr<MemoryProvider> mem;
  const std::shared_ptr<TypeProvider> types;
};

TEST_SUITE("BrightenPointers") {
  TEST_CASE_FIXTURE(BrightenPointersFixture,
                    "Run the whole pass on a well-formed function") {

    auto mod = LoadTestData(llvm_context, "gep_add.ll");
    LifterOptions options(arch.get(), mod.get());
    EntityLifter lifter(options, mem, types);

    auto module = RunFunctionPass(llvm_context, "gep_add.ll",
                                  CreateBrightenPointerOperations(lifter));

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
  TEST_CASE_FIXTURE(BrightenPointersFixture, "multiple_bitcast") {
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
