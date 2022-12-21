#include <anvill/Passes/ReplaceRemillFunctionReturnsWithAnvillFunctionReturns.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/IntrinsicTable.h>

#include <vector>

#include "Utils.h"
#include "anvill/Declarations.h"

namespace anvill {
llvm::StringRef
ReplaceRemillFunctionReturnsWithAnvillFunctionReturns::name(void) {
  return "ReplaceRemillFunctionReturnsWithAnvillFunctionReturns";
}


llvm::PreservedAnalyses
ReplaceRemillFunctionReturnsWithAnvillFunctionReturns::runOnBasicBlockFunction(
    llvm::Function &F, llvm::FunctionAnalysisManager &AM,
    const anvill::BasicBlockContext &bbcont) {

  std::vector<llvm::CallBase *> to_replace;
  for (auto &insn : llvm::instructions(F)) {
    if (llvm::CallBase *call = llvm::dyn_cast<llvm::CallBase>(&insn)) {
      if (call->getCalledFunction() &&
          call->getCalledFunction()->getName().startswith(
              "__remill_function_return")) {

        to_replace.push_back(call);
      }
    }
  }


  const std::vector<ValueDecl> &ret_decl = bbcont.ReturnValue();
  remill::IntrinsicTable intrinsics(F.getParent());
  auto pres_analyses = llvm::PreservedAnalyses::all();
  for (auto rep : to_replace) {
    auto state = rep->getArgOperand(0);
    auto mem = rep->getArgOperand(2);
    llvm::IRBuilder<> ir(rep);
    ir.SetInsertPoint(rep);


    std::vector<llvm::Value *> args;
    for (auto vdecl : ret_decl) {
      args.push_back(anvill::LoadLiftedValue(
          vdecl, this->lifter.Options().TypeDictionary(), intrinsics, ir, state,
          mem));
    }

    auto tgt = GetOrCreateAnvillReturnFunc(F.getParent());
    ir.CreateCall(tgt, args);

    rep->replaceAllUsesWith(mem);
    rep->eraseFromParent();
    pres_analyses = llvm::PreservedAnalyses::none();
  }

  CHECK(!llvm::verifyFunction(F, &llvm::errs()));

  return pres_analyses;
}
}  // namespace anvill