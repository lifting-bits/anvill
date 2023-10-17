#include <anvill/Passes/RewriteVectorOps.h>
#include <glog/logging.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>
#include <remill/BC/Util.h>

#include <optional>
#include <utility>
#include <vector>
// Goal here is to rewrite vector twiddling to integer ops
/*
  %.sroa.23.24.vec.expand = shufflevector <4 x i8> %11, <4 x i8> poison, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 poison, i32 poison, i32 poison, i32 poison>
  %.sroa.23.28.vec.expand = shufflevector <4 x i8> %12, <4 x i8> poison, <8 x i32> <i32 poison, i32 poison, i32 poison, i32 poison, i32 0, i32 1, i32 2, i32 3>
  %.sroa.23.28.vecblend = shufflevector <8 x i8> %.sroa.23.24.vec.expand, <8 x i8> %.sroa.23.28.vec.expand, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 12, i32 13, i32 14, i32 15>

  so in this case well get something like (le):
    a = shl(zext(%12)), 32
    b = zext(11)
    c=or(a,b)

*/
namespace anvill {

llvm::StringRef RewriteVectorOps::name(void) {
  return "RewriteVectorOps";
}

std::optional<llvm::IntegerType *> IntegerTypeForVector(llvm::VectorType *vec) {
  if (!vec->isScalableTy()) {
    return llvm::IntegerType::get(
        vec->getContext(), vec->getPrimitiveSizeInBits().getFixedValue());
  }
  return std::nullopt;
}

struct RewrittenInteger {
  llvm::Value *target;
  llvm::IntegerType *to_int_ty;
  std::pair<uint32_t, uint32_t> bit_range;
  uint32_t bitshift;
  bool poison;
};

struct DecomposeState {
  uint32_t curr_index;
  const llvm::ShuffleVectorInst &sv;


  bool ConsumedAll() {
    return curr_index >= sv.getShuffleMask().size();
  }

  uint32_t GetOpLengths() {
    auto v = llvm::cast<llvm::VectorType>(sv.getOperand(0)->getType());
    return v->getElementCount().getKnownMinValue();
  }

  bool isInSameVec(uint32_t ind1, uint32_t ind2) {
    return (ind1 < GetOpLengths() && ind2 < GetOpLengths()) ||
           (ind1 >= GetOpLengths() && ind2 >= GetOpLengths());
  }


  std::optional<uint32_t> ElementSize() {
    auto ty = llvm::cast<llvm::VectorType>(this->sv.getOperand(0)->getType());
    auto el_ty = ty->getElementType();
    auto sz = el_ty->getPrimitiveSizeInBits();
    if (sz) {
      return sz;
    }

    return std::nullopt;
  }


  std::optional<RewrittenInteger> ConsumeNext() {
    uint32_t start_index = this->curr_index;
    int first_end = sv.getMaskValue(this->curr_index);
    int prev_ind = first_end;
    this->curr_index += 1;
    LOG(INFO) << "first: " << first_end;
    while (!this->ConsumedAll()) {
      auto next = sv.getMaskValue(this->curr_index);
      LOG(INFO) << "next: " << next;
      // we can either group poisons or sequences
      if (!(next == llvm::PoisonMaskElem && prev_ind == llvm::PoisonMaskElem) &&
          (!isInSameVec(prev_ind, next) || prev_ind + 1 != next)) {
        break;
      }

      prev_ind = next;
      this->curr_index += 1;
    }


    bool is_first_op = first_end < static_cast<int>(GetOpLengths());

    llvm::Value *target = is_first_op ? sv.getOperand(0) : sv.getOperand(1);
    std::pair<uint32_t, uint32_t> element_range = std::make_pair(0, 0);
    auto poison = first_end == llvm::PoisonMaskElem;
    if (!poison) {
      element_range = std::make_pair(first_end, prev_ind + 1);
      if (!is_first_op) {
        element_range.first = element_range.first - GetOpLengths();
        element_range.second = element_range.second - GetOpLengths();
      }
    }  // the prev_ind is the last inclusive indice so bump one to make this an [) range
    // convert the element range into a bit range
    CHECK(element_range.second >= element_range.first);
    auto sz = this->ElementSize();
    if (!sz) {
      return std::nullopt;
    }

    std::pair<uint32_t, uint32_t> bit_range;
    // first member of the range is the lshr for cutting off low bits
    // second describes the mask
    if (sv.getModule()->getDataLayout().isLittleEndian()) {
      bit_range =
          std::make_pair(element_range.first * *sz, element_range.second * *sz);
    } else {
      bit_range = std::make_pair((GetOpLengths() - element_range.second) * *sz,
                                 (GetOpLengths() - element_range.first) * *sz);
    }

    auto ity =
        IntegerTypeForVector(llvm::cast<llvm::VectorType>(target->getType()));
    if (!ity) {
      return std::nullopt;
    }
    uint32_t bitshift;
    if (sv.getModule()->getDataLayout().isLittleEndian()) {
      bitshift = *sz * start_index;
    } else {
      auto op_distance = sv.getType()->getElementCount().getFixedValue() -
                         (element_range.second - element_range.first);
      LOG(INFO) << remill::LLVMThingToString(target);
      LOG(INFO) << "odist: " << op_distance;
      LOG(INFO) << "start_ind: " << start_index;
      LOG(INFO) << "diff: " << (op_distance - start_index);
      bitshift = *sz * (op_distance - start_index);
    }
    return RewrittenInteger{target, *ity, bit_range, bitshift, poison};
  }
};

// this isnt super smart but we just check if
// each vector is extracted once
std::optional<std::vector<RewrittenInteger>>
Rewrite(const llvm::ShuffleVectorInst &sv) {
  std::vector<RewrittenInteger> rewrites;
  DecomposeState st{0, sv};
  while (!st.ConsumedAll()) {
    auto nxt = st.ConsumeNext();
    if (!nxt) {
      return std::nullopt;
    }
    rewrites.push_back(*nxt);
  }
  return rewrites;
}


llvm::PreservedAnalyses
RewriteVectorOps::run(llvm::Function &F, llvm::FunctionAnalysisManager &AM) {
  std::vector<llvm::ShuffleVectorInst *> svs;
  for (auto &insn : llvm::instructions(F)) {
    if (llvm::ShuffleVectorInst *sv =
            llvm::dyn_cast<llvm::ShuffleVectorInst>(&insn)) {
      svs.push_back(sv);
    }
  }

  auto pres = llvm::PreservedAnalyses::all();
  for (auto sv : svs) {
    auto vec_type = sv->getType();
    if (vec_type->isScalableTy()) {
      LOG(ERROR) << "Could not rewrite sv, unable to rewrite scalable type"
                 << remill::LLVMThingToString(sv);
      continue;
    }

    auto maybe_rws = Rewrite(*sv);
    if (!maybe_rws) {
      LOG(ERROR) << "Could not rewrite sv, unable to split"
                 << remill::LLVMThingToString(sv);
      continue;
    }
    auto rws = *maybe_rws;
    auto base_int_ty = llvm::IntegerType::get(
        F.getContext(), vec_type->getScalarSizeInBits() *
                            vec_type->getElementCount().getFixedValue());
    llvm::Value *base_value = llvm::Constant::getNullValue(base_int_ty);
    llvm::IRBuilder<> ir(sv);
    for (const auto &rw : rws) {
      // it must be vector as it's an operand to llvm
      if (!rw.poison) {
        auto init_int = ir.CreateBitCast(rw.target, rw.to_int_ty);

        auto casted = ir.CreateZExtOrTrunc(init_int, base_int_ty);
        auto target_itype =
            llvm::IntegerType::get(F.getContext(), rw.bit_range.second);
        auto dropped_high_bits = ir.CreateAnd(
            casted,
            llvm::ConstantInt::get(base_int_ty, target_itype->getBitMask()));
        auto extracted = ir.CreateLShr(dropped_high_bits, rw.bit_range.first);
        auto placed = ir.CreateShl(extracted, rw.bitshift);
        base_value = ir.CreateOr(base_value, placed);
      }
    }
    auto r = ir.CreateBitCast(base_value, vec_type);
    sv->replaceAllUsesWith(r);
    sv->eraseFromParent();
    pres = llvm::PreservedAnalyses::none();
  }

  return pres;
}


}  // namespace anvill