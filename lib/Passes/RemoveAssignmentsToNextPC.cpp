#include <anvill/ABI.h>
#include <anvill/Passes/RemoveAssignmentsToNextPC.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/Util.h>

#include <optional>

#include "Utils.h"

namespace anvill {

llvm::StringRef RemoveAssignmentsToNextPC::name(void) {
  return "Replace stack references";
}


namespace {
std::optional<llvm::StoreInst *>
UniqueAssignmentToNextPc(llvm::Function *func) {
  auto target_arg = remill::NthArgument(func, remill::kNumBlockArgs);

  if (target_arg->getNumUses() == 1) {
    if (auto *user =
            llvm::dyn_cast<llvm::StoreInst>(*target_arg->user_begin())) {
      return user;
    }
  }

  return std::nullopt;
}


llvm::Function *GetOrCreateGotoInstrinsic(llvm::Module *mod,
                                          llvm::IntegerType *addr_ty) {
  auto fun = mod->getFunction(anvill::kAnvillGoto);
  if (fun) {
    return fun;
  }
  auto tgt_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(mod->getContext()), {addr_ty}, false);
  return llvm::Function::Create(tgt_type, llvm::GlobalValue::ExternalLinkage,
                                anvill::kAnvillGoto, mod);
}


llvm::BasicBlock *CreateTargetBlock(llvm::Value *mem_val, llvm::Constant *c,
                                    llvm::Function *func,
                                    llvm::Function *intrinsic) {
  auto bb = llvm::BasicBlock::Create(func->getContext(), "", func);

  llvm::IRBuilder<> ir(bb);
  ir.CreateCall(intrinsic, {c});
  ir.CreateRet(mem_val);

  return bb;
}

}  // namespace


namespace pats = llvm::PatternMatch;
llvm::PreservedAnalyses RemoveAssignmentsToNextPC::runOnBasicBlockFunction(
    llvm::Function &F, llvm::FunctionAnalysisManager &AM,
    const anvill::BasicBlockContext &cont, const FunctionDecl &) {

  auto next_pc_assign = UniqueAssignmentToNextPc(&F);
  auto maybe_unique_ret = UniqueReturn(&F);
  if (!next_pc_assign || !maybe_unique_ret) {
    return llvm::PreservedAnalyses::all();
  }

  auto unique_ret = *maybe_unique_ret;


  auto stored = (*next_pc_assign)->getValueOperand();
  // now we have threes cases we can handle: constant in which case terminate with a goto, select on constant, create a terminating if goto,
  // non constant (now we could try to recover a jump table here, but instead just switch on the stored pc value)
  // TODO(Ian): we may be able to use the jump table analysis here to recover more idiomatic switching.. we are essentially re-doing anvill complete switch here
  llvm::Constant *first{nullptr};
  llvm::Constant *second{nullptr};
  llvm::Value *condition{nullptr};

  auto goto_instrinsic = GetOrCreateGotoInstrinsic(
      F.getParent(), this->lifter.Options().arch->AddressType());
  if (pats::match(stored, pats::m_Constant(first))) {
    // TODO(Ian): should probably check pc taint
    llvm::IRBuilder<> ir(unique_ret);
    ir.CreateCall(goto_instrinsic, {first});
    (*next_pc_assign)->eraseFromParent();
  } else if (pats::match(stored, pats::m_Select(pats::m_Value(condition),
                                                pats::m_Constant(first),
                                                pats::m_Constant(second)))) {
    auto mem = unique_ret->getReturnValue();
    llvm::IRBuilder<> ir(unique_ret->getParent());
    unique_ret->eraseFromParent();
    auto f = CreateTargetBlock(mem, first, &F, goto_instrinsic);
    auto s = CreateTargetBlock(mem, second, &F, goto_instrinsic);
    ir.CreateCondBr(condition, f, s);
    (*next_pc_assign)->eraseFromParent();
  } else {
    // not supported yet
    return llvm::PreservedAnalyses::all();
  }

  CHECK(!llvm::verifyFunction(F, &llvm::errs()));

  return llvm::PreservedAnalyses::none();
}

}  // namespace anvill