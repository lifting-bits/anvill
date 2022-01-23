#include <anvill/Passes/CombineAdjacentShifts.h>
#include <anvill/Transforms.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PatternMatch.h>

#include "Utils.h"

namespace anvill {

namespace {

// Identify `(ashr (shl V, A), B)` and try to convert to
//
//        V_short = trunc V to iA
//        V_signed = sext V_short
//        res = shl V_signed, A - B
static bool FoldAshrSlh(llvm::Function &func) {
  struct SignExtendMatch {
    uint64_t shift_left;
    uint64_t shift_right;
    llvm::IntegerType *full_type;
    llvm::Value *int_ptr;
    llvm::Instruction *ashr;
  };

  auto &context = func.getContext();

  std::vector<SignExtendMatch> matches;
  for (auto &insn : llvm::instructions(func)) {
    namespace pats = llvm::PatternMatch;

    SignExtendMatch sem;
    if (!pats::match(
            &insn,
            pats::m_AShr(pats::m_Shl(pats::m_Value(sem.int_ptr),
                                     pats::m_ConstantInt(sem.shift_right)),
                         pats::m_ConstantInt(sem.shift_left)))) {
      continue;
    }

    sem.full_type = llvm::dyn_cast<llvm::IntegerType>(sem.int_ptr->getType());
    if (!sem.full_type) {
      continue;
    }

    // Make sure that we're a shift by half the size of the integer type. When
    // the shift right is then smaller than the shl, it narrows us to looking
    // at only the pattern of shifting a (narrower) signed value left, that
    // happens to be stored in a wider value.
    auto orig_size = sem.full_type->getIntegerBitWidth();
    if (sem.shift_left > sem.shift_right &&
        ((sem.shift_left * 2u) == orig_size)) {

      sem.ashr = &insn;
      matches.push_back(sem);
    }
  }

  for (auto mat : matches) {
    auto new_shl_amount = mat.shift_left - mat.shift_right;

    auto half_type = llvm::IntegerType::get(context, mat.shift_left);

    auto trunc = new llvm::TruncInst(mat.int_ptr, half_type, "", mat.ashr);
    auto sext = new llvm::SExtInst(trunc, mat.full_type, "", mat.ashr);
    auto shl = llvm::BinaryOperator::Create(
        llvm::BinaryOperator::BinaryOps::Shl, sext,
        llvm::ConstantInt::get(mat.full_type, new_shl_amount), "", mat.ashr);

    anvill::CopyMetadataTo(mat.int_ptr, trunc);
    anvill::CopyMetadataTo(mat.ashr, sext);
    anvill::CopyMetadataTo(mat.ashr->getOperand(0u), shl);
    mat.ashr->replaceAllUsesWith(shl);
    mat.ashr->eraseFromParent();
  }

  return !matches.empty();
}

}  // namespace


void AddCombineAdjacentShifts(llvm::FunctionPassManager &fpm) {
  fpm.addPass(CombineAdjacentShifts());
}

llvm::PreservedAnalyses
CombineAdjacentShifts::run(llvm::Function &func,
                           llvm::FunctionAnalysisManager &fam) {

  if (FoldAshrSlh(func)) {
    return llvm::PreservedAnalyses::none();
  }

  return llvm::PreservedAnalyses::all();
}


llvm::StringRef CombineAdjacentShifts::name(void) {
  return "CombineAdjacentShifts";
}


}  // namespace anvill