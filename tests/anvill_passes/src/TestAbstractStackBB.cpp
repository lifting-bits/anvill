

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


class BasicBlockContext {
 public:
  virtual const std::vector<ParameterDecl> &GetAvailableVariables() const = 0;
};

struct AnvillBasicBlock {
  llvm::Function *func;
  const BasicBlockContext &context;
};


class InitializeRegisterParameterPass {
 private:
  AnvillBasicBlock basic_block;
  remill::Arch::ArchPtr arch;


 public:
  InitializeRegisterParameterPass(AnvillBasicBlock basic_block_)
      : basic_block(basic_block_) {}


  llvm::Function *BuildNewFunc() {

    std::vector<llvm::Type *> args(
        basic_block.func->getFunctionType()->param_begin(),
        basic_block.func->getFunctionType()->param_end());

    auto num_bb_params = args.size();
    auto vars = this->basic_block.context.GetAvailableVariables();
    for (const auto &v : vars) {
      args.push_back(v.type);
    }

    auto ntype = llvm::FunctionType::get(
        this->basic_block.func->getReturnType(), args, false);

    auto nfunc = llvm::Function::Create(
        ntype, llvm::GlobalValue::ExternalLinkage,
        this->basic_block.func->getName(), this->basic_block.func->getParent());


    llvm::ValueToValueMapTy mp;
    llvm::SmallVector<llvm::ReturnInst *, 10> rets;
    llvm::CloneFunctionInto(nfunc, this->basic_block.func, mp,
                            llvm::CloneFunctionChangeType::LocalChangesOnly,
                            rets);

    nfunc->dump();

    return nfunc;
  }


  void run() {}
};

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


class MockBasicBlockContext : BasicBlockContext {
  std::vector<ParameterDecl> paramdecls;

 public:
  virtual const std::vector<ParameterDecl> &GetAvailableVariables() const = 0;
};

TEST_SUITE("Basic Block tests") {
  TEST_CASE("Convert parameters") {
    auto llvm_context = anvill::CreateContextWithOpaquePointers();
    auto module = LoadTestData(*llvm_context, "MainBasicBlocks.ll");
    auto bb_func = module->getFunction("basic_block_func4199701");
    bb_func->dump();
  }
}
}  // namespace anvill