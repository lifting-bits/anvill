/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <anvill/Analysis/CrossReferenceResolver.h>

#include <anvill/ABI.h>
#include <anvill/Analysis/Utils.h>
#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Lifters/Options.h>

#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include <remill/BC/Util.h>

#include <unordered_map>

namespace anvill {
namespace {

using ResolverFuncType = std::function<std::optional<uint64_t>(llvm::GlobalValue *)>;

// Convert an unsigned value `val` of size `size` bits into a signed `int64_t`.
static int64_t Signed(uint64_t val, uint64_t size) {
  switch (size) {
    case 1:
      if (val & 1) {
        return -1;
      } else {
        return 0;
      }
    case 8: return static_cast<int8_t>(val);
    case 16: return static_cast<int16_t>(val);
    case 32: return static_cast<int8_t>(val);
    case 64: return static_cast<int64_t>(val);
    default:
      const uint64_t m = 1ull << (size - 1ull);
      return static_cast<int64_t>(((val ^ m) - m));
  }
}

}  // namespace

class CrossReferenceResolverImpl {
 public:
  CrossReferenceResolverImpl(const llvm::DataLayout &dl_,
                             ResolverFuncType address_of_entity_)
      : dl(dl_),
        address_of_entity(address_of_entity_) {}

  ResolvedCrossReference ResolveConstant(llvm::Constant *const_val);
  ResolvedCrossReference ResolveGlobalValue(llvm::GlobalValue *const_val);
  ResolvedCrossReference ResolveConstantExpr(llvm::ConstantExpr *const_val);

  // Try to resolve `val` as a cross-reference.
  ResolvedCrossReference ResolveValue(llvm::Value *val);

  // Merge and saturate the flags of `lhs` and `rhs`. It is acceptable for
  // `lhs` or `rhs` to promote pointerness.
  template <typename Op>
  ResolvedCrossReference Merge(ResolvedCrossReference lhs,
                               ResolvedCrossReference rhs,
                               Op &&merge_vals);

  // Merge and saturate the flags of `lhs` and `rhs`. It is acceptable for
  // `lhs` to promote pointerness, but not `rhs`.
  template <typename Op>
  ResolvedCrossReference MergeLeft(ResolvedCrossReference lhs,
                                   ResolvedCrossReference rhs,
                                   Op &&merge_vals);

  // Return the size of the type `type`.
  uint64_t SizeOfType(llvm::Type *type);


#define NO_WRAP(val, size) val
#define SIGNED_WRAP(val, size) Signed(val, size)
#define MAKE_BINOP_FOLDER(name, op, merge, wrap, allow_rhs_zero) \
    ResolvedCrossReference Fold ## name(ResolvedCrossReference lhs_xr, \
                                        ResolvedCrossReference rhs_xr, \
                                        uint64_t mask, uint64_t size) { \
      if (allow_rhs_zero || rhs_xr.u.address & mask) { \
        return merge(lhs_xr, rhs_xr, \
                     [=] (uint64_t lhs, uint64_t rhs) { \
                        return static_cast<uint64_t>( \
                            (wrap(lhs, size) op wrap(rhs, size))) & mask; \
                     }); \
      } else { \
        return {}; \
      } \
    }

  MAKE_BINOP_FOLDER(Add, +, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(Sub, -, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(Mul, *, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(And, &, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(Or, |, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(Xor, ^, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(Shl, <<, MergeLeft, NO_WRAP, true)
  MAKE_BINOP_FOLDER(LShr, >>, MergeLeft, NO_WRAP, true)
  MAKE_BINOP_FOLDER(AShr, >>, MergeLeft, SIGNED_WRAP, true)
  MAKE_BINOP_FOLDER(UDiv, /, MergeLeft, NO_WRAP, false)
  MAKE_BINOP_FOLDER(URem, %, MergeLeft, NO_WRAP, false)
  MAKE_BINOP_FOLDER(SDiv, /, MergeLeft, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(SRem, %, MergeLeft, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(ICmpEq, ==, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpNe, !=, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpUgt,>, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpUge, >=, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpUlt, <, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpUle, <, Merge, NO_WRAP, true)
  MAKE_BINOP_FOLDER(ICmpSgt, >, Merge, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(ICmpSge, >=, Merge, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(ICmpSlt, <, Merge, SIGNED_WRAP, false)
  MAKE_BINOP_FOLDER(ICmpSle, <=, Merge, SIGNED_WRAP, false)

#undef MAKE_BINOP_FOLDER
#undef NO_WRAP
#undef SIGNED_WRAP

  ResolvedCrossReference FoldICmp(ResolvedCrossReference lhs_xr,
                                  ResolvedCrossReference rhs_xr, uint64_t mask,
                                  uint64_t size, unsigned pred) {
    switch (pred) {
      case llvm::CmpInst::ICMP_EQ:
        return FoldICmpEq(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_NE:
        return FoldICmpNe(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_UGT:
        return FoldICmpUgt(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_UGE:
        return FoldICmpUge(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_ULT:
        return FoldICmpUlt(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_ULE:
        return FoldICmpUle(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_SGT:
        return FoldICmpSgt(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_SGE:
        return FoldICmpSge(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_SLT:
        return FoldICmpSlt(lhs_xr, rhs_xr, mask, size);
      case llvm::CmpInst::ICMP_SLE:
        return FoldICmpSle(lhs_xr, rhs_xr, mask, size);
      default:
        return {};
    }
  }

  const llvm::DataLayout dl;

  // Entity address resolver for figuring out the address of globals/functions.
  const ResolverFuncType address_of_entity;

  // Cache of resolved values.
  std::unordered_map<llvm::Value *, ResolvedCrossReference> xref_cache;
};


// Merge and saturate the flags of `lhs` and `rhs`. It is acceptable for
// `lhs` or `rhs` to promote pointerness.
template <typename Op>
ResolvedCrossReference CrossReferenceResolverImpl::Merge(
    ResolvedCrossReference lhs, ResolvedCrossReference rhs, Op &&merge_vals) {
  ResolvedCrossReference xr = {};
  xr.u.address = merge_vals(lhs.u.address, rhs.u.address);
  xr.is_valid = lhs.is_valid & rhs.is_valid;
  xr.references_entity = lhs.references_entity | rhs.references_entity;
  xr.references_global_value = lhs.references_global_value |
                               rhs.references_global_value;
  xr.references_program_counter = lhs.references_program_counter |
                                  rhs.references_program_counter;
  xr.references_return_address = lhs.references_return_address |
                                 rhs.references_return_address;
  xr.references_stack_pointer = lhs.references_stack_pointer |
                                rhs.references_stack_pointer;
  xr.hinted_value_type = nullptr;
  xr.displacement_from_hinted_value_type = 0;

  if (lhs.hinted_value_type && rhs.hinted_value_type) {
    // Not clear how to combine, so drop the type info. E.g. we could be
    // dealing with a `ptrdiff_t` logically, i.e. the distance between
    // two pointers.

    // TODO(pag): Think more about the difference between two entities
    //            case. It might be that we don't want to actually fold
    //            this type of symbolic expression down.

  } else if (lhs.hinted_value_type) {
    const auto diff = xr.u.displacement - lhs.u.displacement;
    xr.hinted_value_type = lhs.hinted_value_type;
    xr.displacement_from_hinted_value_type =
        lhs.displacement_from_hinted_value_type + diff;

  } else if (rhs.hinted_value_type) {
    const auto diff = xr.u.displacement - rhs.u.displacement;
    xr.hinted_value_type = rhs.hinted_value_type;
    xr.displacement_from_hinted_value_type =
        rhs.displacement_from_hinted_value_type + diff;
  }

  return xr;
}

// Merge and pick the flags of `lhs` and `rhs`. It is acceptable for
// `lhs` to promote pointerness, but not `rhs`.
template <typename Op>
ResolvedCrossReference CrossReferenceResolverImpl::MergeLeft(
    ResolvedCrossReference lhs, ResolvedCrossReference rhs, Op &&merge_vals) {
  ResolvedCrossReference xr = {};
  xr.u.address = merge_vals(lhs.u.address, rhs.u.address);
  xr.is_valid = lhs.is_valid & rhs.is_valid;
  xr.references_entity = lhs.references_entity;
  xr.references_global_value = lhs.references_global_value;
  xr.references_program_counter = lhs.references_program_counter;
  xr.references_return_address = lhs.references_return_address;
  xr.references_stack_pointer = lhs.references_stack_pointer;
  xr.hinted_value_type = lhs.hinted_value_type;
  xr.displacement_from_hinted_value_type +=
      static_cast<int64_t>(xr.u.address - lhs.u.address);
  return xr;
}

// Try to resolve a constant to a cross-reference.
ResolvedCrossReference CrossReferenceResolverImpl::ResolveConstant(
    llvm::Constant *const_val) {

  auto it = xref_cache.find(const_val);
  if (it != xref_cache.end()) {
    return it->second;
  }

  auto &xr = xref_cache[const_val];

  if (auto gv = llvm::dyn_cast<llvm::GlobalValue>(const_val)) {
    xr = ResolveGlobalValue(gv);

  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(const_val)) {
    xr = ResolveConstantExpr(ce);

  } else if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(const_val)) {
    xr.u.address = ci->getZExtValue();
    xr.is_valid = true;

  } else if (auto cpn = llvm::dyn_cast<llvm::ConstantPointerNull>(const_val)) {
    xr.hinted_value_type = cpn->getType()->getElementType();
    xr.is_valid = true;

  } else {
    xr.is_valid = false;
  }

  return xr;
}

ResolvedCrossReference CrossReferenceResolverImpl::ResolveGlobalValue(
    llvm::GlobalValue *gv) {

  ResolvedCrossReference xr = {};

  if (auto var = llvm::dyn_cast<llvm::GlobalVariable>(gv)) {
    if (IsProgramCounter(gv)) {
      xr.references_program_counter = true;
      xr.is_valid = true;
      return xr;

    } else if (IsStackPointer(gv)) {
      xr.references_stack_pointer = true;
      xr.is_valid = true;
      return xr;

    } else if (IsReturnAddress(gv)) {
      xr.references_return_address = true;
      xr.is_valid = true;
      return xr;
    }
  }

  xr.references_global_value = true;

  if (auto maybe_addr = address_of_entity(gv); maybe_addr) {
    xr.u.address = *maybe_addr;
    xr.references_entity = true;
    xr.is_valid = true;
  }

  auto [base, offset] = remill::StripAndAccumulateConstantOffsets(dl, gv);
  if (base) {
    xr.hinted_value_type = base->getType()->getPointerElementType();
    xr.displacement_from_hinted_value_type = offset;

  } else if (!llvm::isa<llvm::Function>(gv)) {
    xr.hinted_value_type = gv->getValueType();
    xr.displacement_from_hinted_value_type = 0;
  }

  return xr;
}

ResolvedCrossReference CrossReferenceResolverImpl::ResolveConstantExpr(
    llvm::ConstantExpr *ce) {

  const auto ptr_size = dl.getPointerSizeInBits(0);
  const uint64_t size = ce->getOperand(0)->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const uint64_t out_size = ce->getType()->getPrimitiveSizeInBits();
  const uint64_t out_mask = out_size < 64 ? (1ull << out_size) - 1ull : ~0ull;

  switch (ce->getOpcode()) {
    default:
      break;

#define FOLD_CASE(name) \
    case llvm::Instruction::name: \
      return Fold ## name (ResolveConstant(ce->getOperand(0)), \
                           ResolveConstant(ce->getOperand(1)), \
                           mask, size);

    FOLD_CASE(Add)
    FOLD_CASE(Sub)
    FOLD_CASE(Mul)
    FOLD_CASE(And)
    FOLD_CASE(Or)
    FOLD_CASE(Xor)
    FOLD_CASE(Shl)
    FOLD_CASE(LShr)
    FOLD_CASE(AShr)
    FOLD_CASE(SDiv)
    FOLD_CASE(UDiv)
    FOLD_CASE(SRem)
    FOLD_CASE(URem)

#undef FOLD_CASE

    case llvm::Instruction::ZExt: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.u.address &= mask;
      return xr;
    }

    case llvm::Instruction::SExt: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.u.displacement = Signed(xr.u.address, size);
      xr.u.address &= out_mask;
      return xr;
    }

    case llvm::Instruction::Trunc: {
      auto xr = ResolveConstant(ce->getOperand(0));
      xr.u.address &= out_mask;
      return xr;
    }

    // TODO(pag): Mark as pointers?
    case llvm::Instruction::IntToPtr:
    case llvm::Instruction::PtrToInt:
    case llvm::Instruction::BitCast:
      return ResolveConstant(ce->getOperand(0));

    case llvm::Instruction::ICmp: {
      return FoldICmp(ResolveConstant(ce->getOperand(0)),
                      ResolveConstant(ce->getOperand(1)),
                      mask, size, ce->getPredicate());
    }

    case llvm::Instruction::GetElementPtr: {
      auto base = ResolveConstant(ce->getOperand(0));

      // In the event that an index is non-constant, we'll try to also resolve
      // it using our value resolver.
      auto visit = [=] (llvm::Value &val, llvm::APInt &ap) -> bool {
        if (const auto index_xr = ResolveValue(&val); index_xr.is_valid) {
          ap += static_cast<uint64_t>(Signed(index_xr.u.address, ptr_size));
          return true;
        } else {
          return false;
        }
      };

      const auto gep = llvm::dyn_cast<llvm::GEPOperator>(ce);
      llvm::APInt ap(ptr_size, 0);
      if (!gep->accumulateConstantOffset(dl, ap, visit)) {
        base.is_valid = false;
        return base;
      }

      const auto disp = Signed(ap.getZExtValue(), ptr_size);
      base.u.address += static_cast<uint64_t>(disp);
      base.displacement_from_hinted_value_type += disp;
      return base;
    }

    // TODO(pag): Consider doing merge on both sides.
    // TODO(pag): What happens if there's a `trunc` on a pointer and that is
    //            the condition?
    case llvm::Instruction::Select: {
      auto cond = ResolveConstant(ce->getOperand(0));
      ResolvedCrossReference selected_val = {};
      if (cond.u.address) {
        selected_val = ResolveConstant(ce->getOperand(1));
      } else {
        selected_val = ResolveConstant(ce->getOperand(2));
      }
      selected_val.is_valid &= cond.is_valid;
      return selected_val;
    }
  }

  return {};
}

// Try to resolve `val` as a cross-reference.
ResolvedCrossReference CrossReferenceResolverImpl::ResolveValue(
    llvm::Value *val) {
  if (auto const_val = llvm::dyn_cast<llvm::Constant>(val)) {
    return ResolveConstant(const_val);

  // TODO(pag): Eventually try to deal with instructions. Key issues are that
  //            we can't cache their results. Possible opportunities are that
  //            we could have an API that takes a `DominorTree` and thus
  //            communicates that the user won't invalidate the dominator tree
  //            results while using the API, and then we can possibly do folding
  //            of things like `select` instructions, and possible `phi` nodes.
  } else {
    return {};
  }
}

CrossReferenceResolver::~CrossReferenceResolver(void) {}

// The primary way of using a cross-reference resolver is with an entity
// lifter that can resolve global references on our behalf.
CrossReferenceResolver::CrossReferenceResolver(const EntityLifter &lifter)
    : impl(std::make_shared<CrossReferenceResolverImpl>(
        lifter.Options().module->getDataLayout(),
        [=] (llvm::GlobalValue *entity) {
          return lifter.AddressOfEntity(entity);
        })) {}

// In the absence of an entity lifter, we need a DataLayout to determine
// offsets, etc.
CrossReferenceResolver::CrossReferenceResolver(const llvm::DataLayout &dl)
    : impl(std::make_shared<CrossReferenceResolverImpl>(
          dl, [] (llvm::GlobalValue *) { return std::nullopt; })) {}

// Clear the internal cache.
void CrossReferenceResolver::ClearCache(void) const {
  impl->xref_cache.clear();
}

// Try to resolve `val` as a cross-reference.
ResolvedCrossReference CrossReferenceResolver::TryResolveReference(
    llvm::Value *val) const {
  return impl->ResolveValue(val);
}

}  // namespace anvill
