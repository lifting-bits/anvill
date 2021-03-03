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

    auto module =
        RunFunctionPass(llvm_context, "gep_add.ll",
                        CreateBrightenPointerOperations());

    // Verify the module
    std::string error_buffer;
    llvm::raw_string_ostream error_stream(error_buffer);

    auto succeeded = llvm::verifyModule(*module.get(), &error_stream) == 0;
    error_stream.flush();

    CHECK(succeeded);
    if (!succeeded) {
      std::string error_message = "Module verification failed";
      if (!error_buffer.empty()) {
        error_message += ": " + error_buffer;
      }

      std::cerr << error_message << std::endl;
    }
  }

}; // namespace anvill