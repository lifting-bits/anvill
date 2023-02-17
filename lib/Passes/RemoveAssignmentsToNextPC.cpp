#include <anvill/Passes/RemoveAssignmentsToNextPC.h>
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

#include <optional>

#include "anvill/ABI.h"

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

std::optional<llvm::ReturnInst *> UniqueReturn(llvm::Function *func) {
  std::optional<llvm::ReturnInst *> r = std::nullopt;
  for (auto &insn : llvm::instructions(func)) {
    if (auto nret = llvm::dyn_cast<llvm::ReturnInst>(&insn)) {
      if (r) {
        return std::nullopt;
      } else {
        r = nret;
      }
    }
  }

  return r;
}

llvm::Function *GetOrCreateGotoInstrinsic(llvm::Module *mod,
                                          llvm::IntegerType *addr_ty) {
  auto fun = mod->getFunction(anvill::kAnvillGoto);
  if (fun) {
    return fun;
  }
  auto tgt_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(mod->getContext()), {addr_ty}, true);


  return llvm::Function::Create(tgt_type, llvm::GlobalValue::ExternalLinkage,
                                anvill::kAnvillGoto, mod);
}

}  // namespace

namespace pats = llvm::PatternMatch;
llvm::PreservedAnalyses RemoveAssignmentsToNextPC::runOnBasicBlockFunction(
    llvm::Function &F, llvm::FunctionAnalysisManager &AM,
    const anvill::BasicBlockContext &) {
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
  llvm::ConstantInt *first{nullptr};
  llvm::ConstantInt *second{nullptr};
  llvm::Value *condition{nullptr};

  auto goto_instrinsic = GetOrCreateGotoInstrinsic(
      F.getParent(), this->lifter.Options().arch->AddressType());
  if (pats::match(stored, pats::m_ConstantInt(first))) {
    llvm::IRBuilder<> ir(unique_ret);
    ir.CreateCall(goto_instrinsic, {first});
    (*next_pc_assign)->eraseFromParent();
  } else if (pats::match(stored, pats::m_Select(pats::m_Value(condition),
                                                pats::m_ConstantInt(first),
                                                pats::m_ConstantInt(second)))) {
  } else {
  }

  CHECK(!llvm::verifyFunction(F, &llvm::errs()));
  return llvm::PreservedAnalyses::none();
}

}  // namespace anvill