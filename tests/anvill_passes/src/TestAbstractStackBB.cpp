

// basic_block_func4199701

#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <anvill/Utils.h>
#include <doctest/doctest.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <remill/Arch/Arch.h>

#include <unordered_set>
#include <vector>

#include "Utils.h"


namespace anvill {


/*
Register pass plan:
1. iterate through all available paramater decls declaring them in the signature.
2. Call StoreNativeValue to store the parameter representing each parameter into the physcal location in the state
3. Apply SROA to the new clone
4. Replace all calls to the basic block function with the clone (should just be one but whatev)
4. When calling the basic block function we now need to call LoadLiftedValue on the parameter decl for each physical location

Stack pass plan:
1. Add a stack parameter that’s just a byte array created in the parent that is the stack size.
2. Identify remill_reads and writes and call something that looks like the xref resolver on them. The only trick is you need to basically record out when you hit a register and then check if that register is holding some stack offset, take the register+stack_offset_in_that_register+the offset computed on the path to finding that register (ie. the xref resolver will be calculating the total displacement along the way)
3. Then we redirect the remill_read to a load from the stack variable at the computed stack offset
4. This could get arbitrarily more complicated when handling expressions built up over multiple registers and array indexing with multiplication over an index register, so there is stuff to work on here (maybe propagating the abstract domain forward as a separate affine analysis)
*/


TEST_SUITE("Basic Block tests") {
  TEST_CASE("Convert parameters") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "MainBasicBlocks.ll");
    auto bb_func = module->getFunction("basic_block_func4199701");
    bb_func->dump();
  }
}
}  // namespace anvill
