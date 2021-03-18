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

void printFunc(const llvm::Module& mod, const std::string& name, const std::string& msg) {
  for (auto& f : mod) {
    if (f.hasName() && f.getName() == name) {
      std::cout << msg << std::endl;
      f.print(llvm::errs(), nullptr);
    }
  }

}
bool checkMod(const llvm::Module& mod) {
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
        mem(MemoryProvider::CreateNullMemoryProvider()),
        types(TypeProvider::CreateNullTypeProvider(llvm_context)) {}

  llvm::LLVMContext llvm_context;
  const remill::Arch::ArchPtr arch;
  const std::shared_ptr<MemoryProvider> mem;
  const std::shared_ptr<TypeProvider> types;
};
*/
bool RunFunctionPass(llvm::Module& module, llvm::FunctionPass *function_pass) {
  llvm::legacy::FunctionPassManager pass_manager(&module);
  pass_manager.add(function_pass);

  pass_manager.doInitialization();

  for (auto &function : module) {
    pass_manager.run(function);
  }

  pass_manager.doFinalization();
  return VerifyModule(&module);
}

TEST_SUITE("BrightenPointers") {
  TEST_CASE("Run the whole pass on a well-formed function") {

    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "gep_add.ll");
    printFunc(*mod, "main", "BEFORE");
    const remill::Arch::ArchPtr arch{remill::Arch::Build(&context, remill::kOSLinux, remill::kArchAMD64)};
    const std::shared_ptr<MemoryProvider> mem{MemoryProvider::CreateNullMemoryProvider()};
    const std::shared_ptr<TypeProvider> types{TypeProvider::CreateNullTypeProvider(context)};

    REQUIRE(mod != nullptr);

    LifterOptions options(arch.get(), *mod.get());
    EntityLifter lifter(options, mem, types);
    CrossReferenceResolver resolver(mod->getDataLayout());
    ValueLifter v_lifter(lifter);
    CHECK(RunFunctionPass(*mod, CreateBrightenPointerOperations(lifter, v_lifter, resolver, 250U)));
    CHECK(checkMod(*mod));
    printFunc(*mod, "main", "AFTER");

  }
/*
  TEST_CASE("multiple_bitcast") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "multiple_bitcast.ll");
    printFunc(*mod, "valid_test", "BEFORE");

    const remill::Arch::ArchPtr arch{remill::Arch::Build(&context, remill::kOSLinux, remill::kArchAMD64)};
    const std::shared_ptr<MemoryProvider> mem{MemoryProvider::CreateNullMemoryProvider()};
    const std::shared_ptr<TypeProvider> types{TypeProvider::CreateNullTypeProvider(context)};
    REQUIRE(mod != nullptr);

    LifterOptions options(arch.get(), *mod.get());
    EntityLifter lifter(options, mem, types);
    CrossReferenceResolver resolver(mod->getDataLayout());
    ValueLifter v_lifter(lifter);
    CHECK(RunFunctionPass(*mod, CreateBrightenPointerOperations(lifter, v_lifter, resolver, 250U)));
    CHECK(checkMod(*mod));
    printFunc(*mod, "valid_test", "AFTER");
}
*/
}

};  // namespace anvill
