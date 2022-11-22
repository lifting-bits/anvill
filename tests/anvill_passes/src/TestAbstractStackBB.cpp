

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