

// basic_block_func4199701

#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <doctest/doctest.h>

#include "Utils.h"


namespace anvill {
TEST_SUITE("Basic Block tests") {
  TEST_CASE("Convert parameters") {
    auto llvm_context = anvill::CreateContextWithOpaquePointers();
    auto module = LoadTestData(*llvm_context, "MainBasicBlocks.ll");
    auto bb_func = module->getFunction("basic_block_func4199701");
    bb_func->dump();
  }
}
}  // namespace anvill