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
#include <remill/BC/Lifter.h>
#include <remill/OS/OS.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <anvill/Analysis/CrossReferenceResolver.h>
#include <iostream>

#include "BaseScenario.h"
#include "Utils.h"

namespace anvill {


bool checkMod(const llvm::Module& mod) {
    // Verify the module
    std::string error_buffer;
    llvm::raw_string_ostream error_stream(error_buffer);

    auto succeeded = llvm::verifyModule(mod, &error_stream) == 0;
    error_stream.flush();

    mod.print(llvm::errs(), nullptr);

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
    REQUIRE(mod != nullptr);

    const auto testme = arch.get();
    LifterOptions options(testme, *mod.get());
    EntityLifter lifter(options, mem, types);
    CrossReferenceResolver resolver(mod->getDataLayout());
    ValueLifter v_lifter(lifter);
    CHECK(RunFunctionPass(mod.get(), CreateBrightenPointerOperations(lifter, v_lifter, resolver, 250U)));
    checkMod(*mod);
  }

  TEST_CASE_FIXTURE(BrightenPointersFixture, "multiple_bitcast") {
    llvm::LLVMContext llvm_context;

    auto mod = LoadTestData(llvm_context, "multiple_bitcast.ll");
    REQUIRE(mod != nullptr);

    const auto testme = arch.get();
    LifterOptions options(testme, *mod.get());
    EntityLifter lifter(options, mem, types);
    CrossReferenceResolver resolver(mod->getDataLayout());
    ValueLifter v_lifter(lifter);
    CHECK(RunFunctionPass(mod.get(), CreateBrightenPointerOperations(lifter, v_lifter, resolver, 250U)));
    checkMod(*mod);
}
}

};  // namespace anvill
