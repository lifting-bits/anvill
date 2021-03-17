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

#include "BrightenPointerOperations.h"

#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Passes/PassBuilder.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Util.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

char PointerLifterPass::ID = '\0';

PointerLifterPass::PointerLifterPass(const EntityLifter &entity_lifter_, const ValueLifter &value_lifter_,
   const CrossReferenceResolver& xref_lifter_, unsigned max_gas_)
    : FunctionPass(ID),
      entity_lifter(entity_lifter_),
      value_lifter(value_lifter_),
      xref_lifter(xref_lifter_),
      max_gas(max_gas_) {}

bool PointerLifterPass::runOnFunction(llvm::Function &f) {
  PointerLifter lifter(&f, max_gas, entity_lifter);
  lifter.LiftFunction(f);

  // TODO (Carson) have an analysis function which determines modifications
  // Then use lift function to run those modifications
  // Can return true/false depending on what was modified
  return true;
}

PointerLifter::PointerLifter(llvm::Function *func_, unsigned max_gas_,
                             const EntityLifter &entity_lifter_)
    : max_gas(max_gas_),
      func(func_),
      mod(func->getParent()),
      context(mod->getContext()),
      i32_ty(llvm::Type::getInt32Ty(context)),
      i8_ty(llvm::Type::getInt8Ty(context)),
      i8_ptr_ty(i8_ty->getPointerTo()),
      dl(mod->getDataLayout()),
      entity_lifter(entity_lifter_),
      value_lifter(entity_lifter),
      xref_resolver(entity_lifter) {}

// Creates a cast of val to a dest type.
// This casts whatever value we want to a pointer, propagating the information
llvm::Value *PointerLifter::getPointerToValue(llvm::IRBuilder<> &ir,
                                              llvm::Value *val,
                                              llvm::Type *dest_type) {

  // is the value another instruction? Visit it
  return ir.CreateBitOrPointerCast(val, dest_type);
}

std::pair<llvm::Value *, bool>
PointerLifter::visitInferInst(llvm::Instruction *inst,
                              llvm::Type *inferred_type) {
  auto &inferred_val_type = inferred_types[inst];
  auto &next_inferred_val_type = next_inferred_types[inst];

  // We're the first ones making an inference.
  if (!inferred_val_type) {
    inferred_val_type = inferred_type;
    next_inferred_val_type = nullptr;
    bool changed = false;
    llvm::Value *first_ret = nullptr;

    // In the process of visiting the instruction, if we come back across
    // ourselves, then `next_inferred_val_type` will be set up to a non-null
    // pointer and we'll re-recurse on that updated value.
    while (inferred_val_type) {
      const auto ret = visit(inst);
      if (!first_ret) {
        first_ret = ret.first;
      }
      if (ret.second) {
        changed = true;
      }

      inferred_val_type = next_inferred_val_type;
      next_inferred_val_type = nullptr;

      // Prevent cycling back and forth.
      if (inferred_val_type == inferred_type) {
        break;
      }
    }

    inferred_val_type = nullptr;
    next_inferred_val_type = nullptr;
    return {first_ret, changed};

  // We are recursively processing the same inference.
  } else if (inferred_val_type == inferred_type) {
    return {inst, false};

  // We're recursively making a /different/ inference than some parent caller.
  // Set it up so that the top-level caller commits to the last nest inferred
  // value type.
  } else {
    next_inferred_val_type = inferred_type;
    return {inst, false};
  }
}


llvm::Value *PointerLifter::GetIndexedPointer(llvm::IRBuilder<> &ir,
                                              llvm::Value *address,
                                              llvm::Value *offset,
                                              llvm::Type *dest_type) const {

  // TODO (Carson) the addr_space is  actually for thread stuff
  // auto i8_ptr_ty = llvm::PointerType::get(i8_ty, addr_space);

  if (auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(offset)) {
    LOG(ERROR) << "Indexed Pointer, RHS const\n";

    const auto rhs_index = static_cast<int32_t>(rhs_const->getSExtValue());

    const auto [new_lhs, index] =
        remill::StripAndAccumulateConstantOffsets(dl, address);

    llvm::GlobalVariable *lhs_global =
        llvm::dyn_cast<llvm::GlobalVariable>(new_lhs);

    if (lhs_global) {
      LOG(ERROR) << "Indexed Pointer, LHS global\n";

      // TODO (Carson) show peter, but this was annoying
      // I expect this function to return a GEP, not abitcast.
      // This function might be more general than what I want
      // if (!index) {
      //    LOG(ERROR) << "Creating bitcast?\n";
      // return ir.CreateBitCast(lhs_global, dest_type);
      // }

      // It's a global variable not associated with a native segment, try to
      // index into it in a natural-ish way. We only apply this when the index
      // is positive.
      if (0 < index) {
        auto offset = static_cast<uint64_t>(index);
        return remill::BuildPointerToOffset(ir, lhs_global, offset, dest_type);
      }
    }

    auto lhs_elem_type = address->getType()->getPointerElementType();
    auto dest_elem_type = dest_type->getPointerElementType();

    const auto lhs_el_size = dl.getTypeAllocSize(lhs_elem_type);
    const auto dest_el_size = dl.getTypeAllocSize(dest_elem_type);

    llvm::Value *ptr = nullptr;

    // If either the source or destination element size is divisible by the
    // other then we might get lucky and be able to compute a pointer to the
    // destination with a single GEP.
    if (!(lhs_el_size % dest_el_size) || !(dest_el_size % lhs_el_size)) {

      if (0 > rhs_index) {
        const auto pos_rhs_index = static_cast<unsigned>(-rhs_index);
        if (!(pos_rhs_index % lhs_el_size)) {
          const auto scaled_index = static_cast<uint64_t>(
              rhs_index / static_cast<int64_t>(lhs_el_size));
          llvm::Value *indices[1] = {
              llvm::ConstantInt::get(i32_ty, scaled_index, true)};
          LOG(ERROR) << "Creating GEP 0?\n";

          ptr = ir.CreateGEP(lhs_elem_type, address, indices);
        }
      } else {
        const auto pos_rhs_index = static_cast<unsigned>(rhs_index);
        if (!(pos_rhs_index % lhs_el_size)) {
          const auto scaled_index = static_cast<uint64_t>(
              rhs_index / static_cast<int64_t>(lhs_el_size));
          llvm::Value *indices[1] = {
              llvm::ConstantInt::get(i32_ty, scaled_index, false)};
          LOG(ERROR) << "Creating GEP 1?\n";

          ptr = ir.CreateGEP(lhs_elem_type, address, indices);
        }
      }
    }

    // We got a GEP for the dest, now make sure it's the right type.
    if (ptr) {
      LOG(ERROR) << "Indexed Pointer, checking types!\n";

      if (address->getType() == dest_type) {
        return ptr;
      } else {
        return ir.CreateBitCast(ptr, dest_type);
      }
    }
  }
  LOG(ERROR) << "Indexed Pointer, treating as byte array?\n";
  auto base = ir.CreateBitCast(address, i8_ptr_ty);
  llvm::Value *indices[1] = {ir.CreateTrunc(offset, i32_ty)};
  auto gep = ir.CreateGEP(i8_ty, base, indices);
  return ir.CreateBitCast(gep, dest_type);
}

// MUST have an implementation of this if llvm:InstVisitor retun type is not
// void.
std::pair<llvm::Value *, bool>
PointerLifter::visitInstruction(llvm::Instruction &inst) {
  LOG(ERROR) << "PointerLifter unknown instruction "
             << remill::LLVMThingToString(&inst) << " in "
             << func->getName().str();
  return {&inst, false};
}
/*
    Replace next_worklist iteration with just a bool `changed`, set changed=true
    here. iterate over the original worklist until changed is false.

    is there a bad recursion case here?

    Create map from Value --> Value, maintains seen/cached changes.
*/

void PointerLifter::ReplaceAllUses(llvm::Value *old_val, llvm::Value *new_val) {
  if (auto old_inst = llvm::dyn_cast<llvm::Instruction>(old_val)) {
    to_remove.insert(old_inst);
    rep_map[old_inst] = new_val;
    made_progress = true;
  } else {
    LOG(ERROR) << "Cannot replace " << remill::LLVMThingToString(old_val)
               << " with " << remill::LLVMThingToString(new_val) << " in "
               << func->getName().str();
  }

  // old_val->replaceAllUsesWith(new_val);
  // TODO Carson, after visitInferInst, remove stuff from the map upon return!
}

/*
BitCasts can give more information about intended types, lets look at this
example

; Function Attrs: noinline
define i64 @valid_test(i64* %0) local_unnamed_addr #1 {
  %2 = bitcast i64* %0 to i8**
  %3 = load i8*, i8** %2, align 8
  %4 = getelementptr i8, i8* %3, i64 36
  %5 = bitcast i8* %4 to i32*
  %6 = load i32, i32* %5, align 4
  %7 = zext i32 %6 to i64
  ret i64 %7
}

Technically, when originally lifting we learned that the parameter is a pointer,
BUT in %2, %3, %4 you can see that its treating the pointer as a raw character
pointer, then in %5 converts it to a i32, which it loads and returns.

After propagating first bitcast it should be

; Function Attrs: noinline
define i64 @valid_test(i8** %0) local_unnamed_addr #1 {
  %3 = load i8*, i8** %0, align 8
  %4 = getelementptr i8, i8* %3, i64 36
  %5 = bitcast i8* %4 to i32*
  %6 = load i32, i32* %5, align 4
  %7 = zext i32 %6 to i64
  ret i64 %7
}

After second bitcast.

; Function Attrs: noinline
define i64 @valid_test(i32** %0) local_unnamed_addr #1 {
  %3 = load i32*, i32** %0, align 8
  %4 = getelementptr i32, i32* %3, i32 9
  %6 = load i32, i32* %4, align 4
  %7 = zext i32 %6 to i64
  ret i64 %7
}
*/
std::pair<llvm::Value *, bool>
PointerLifter::visitBitCastInst(llvm::BitCastInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (inferred_type) {

    // If there is a bitcast that we could not eliminate for some reason (fell
    // through the default case with ERROR). There might be a bitcast downstream
    // which knows more than us, and wants us to update our bitcast. So we just
    // create a new bitcast, replace the current one, and return
    llvm::IRBuilder ir(&inst);
    llvm::Value *new_bitcast =
        ir.CreateBitCast(inst.getOperand(0), inferred_type);
    ReplaceAllUses(&inst, new_bitcast);
    return {new_bitcast, true};
  }
  llvm::Value *possible_pointer = inst.getOperand(0);
  if (auto pointer_inst = llvm::dyn_cast<llvm::Instruction>(possible_pointer)) {

    if (!inst.getDestTy()->isPointerTy()) {
      return {&inst, false};
    }
    // If we are bitcasting to a pointer, propagate that info!
    auto [new_var_type, opt_success] =
        visitInferInst(pointer_inst, inst.getDestTy());
    if (opt_success) {
      ReplaceAllUses(&inst, new_var_type);
      return {new_var_type, true};
    }
    LOG(ERROR) << "Bitcast: Failed to propagate info with pointer_inst: "
               << remill::LLVMThingToString(pointer_inst) << "\n";
    return {&inst, false};
  }
  // TODO (Carson) make sure in the visitor methods that we dont assume inferred
  // type is the return type, we can fail!
  LOG(ERROR) << "BitCast, unknown operand type: "
             << remill::LLVMThingToString(inst.getOperand(0)->getType());
  return {&inst, false};
}

// This function checks for two cases.
// 1. This checks to see if the last index is a const or variable, if it isnt a
//    const we dont rewrite.
// 2. Depending on the offset and inferred type, if the newly calculated offset
//    is not divisible by the type size we don't rewrite.
// This code is taken from Peter's PeelLastIndex :)
bool PointerLifter::canRewriteGep(llvm::GetElementPtrInst &gep,
                                  llvm::Type *inferred_type) {

  llvm::SmallVector<llvm::Value *, 4> indices;
  for (auto it = gep.idx_begin(); it != gep.idx_end(); ++it) {
    indices.push_back(it->get());
  }
  // If the last index isn't a constant then we can't peel it off.
  // Case 1
  auto last_index = llvm::dyn_cast<llvm::ConstantInt>(indices.pop_back_val());
  if (!last_index) {
    return false;
  }

  // Figure out what the last index was represented in terms of a byte offset.
  // We need to be careful about negative indices -- we want to maintain them,
  // but we don't want division/remainder to produce different roundings.
  const auto gep_elem_type_size =
      dl.getTypeAllocSize(gep.getResultElementType()).getFixedSize();
  const auto last_index_i =
      last_index->getSExtValue() * static_cast<int64_t>(gep_elem_type_size);
  const int64_t last_index_ai = std::abs(last_index_i);
  auto elem_size = static_cast<int64_t>(
      dl.getTypeAllocSize(gep.getResultElementType()).getFixedSize());

  // The last index does not evenly divide the size of the result
  // element type. Case 2
  return !(last_index_ai % elem_size);
}
// This function turns GEPS with multiple indicies into multiple geps each with
// one index. Why? Sometimes GEP indexes are not constant, so you cant just
// divide by them all.
std::pair<llvm::Value *, bool>
PointerLifter::flattenGEP(llvm::GetElementPtrInst *gep) {

  // TODO(Carson): Implement me?
  return {gep, false};
}

// TODO (Carson) maybe change back to pointer type.
// TODO (Carson) gep is not a good name for this shenanigans
std::pair<llvm::Value *, bool>
PointerLifter::BrightenGEP_PeelLastIndex(llvm::GetElementPtrInst *gep,
                                         llvm::Type *inferred_type) {

  // TODO (Carson) refactor this to use canRewriteGEP
  LOG(ERROR) << "================================================\n";
  LOG(ERROR) << remill::LLVMThingToString(gep) << " < gep is\n";
  LOG(ERROR) << remill::LLVMThingToString(gep->getType()) << "< gep type\n";
  LOG(ERROR) << gep->getType()->isStructTy() << " < is struct ty? \n";
  LOG(ERROR) << gep->getType()->isVectorTy() << " < is vector ty? \n";
  LOG(ERROR) << gep->getType()->isPointerTy() << " < is pointer ty?\n";
  LOG(ERROR) << remill::LLVMThingToString(inferred_type)
             << " < gep inferred type is\n";

  if (gep->getType()->isPointerTy()) {
    LOG(ERROR) << remill::LLVMThingToString(
                      gep->getType()->getPointerElementType())
               << " < pointer ele type\n";
    LOG(ERROR) << gep->getType()->getPointerElementType()->isStructTy()
               << " < ele is struct?\n";
    if (gep->getType()->getPointerElementType()->isStructTy()) {
      return {gep, false};
    }
  }
  LOG(ERROR) << "------------------------------------------------\n";
  auto src = gep->getPointerOperand();
  LOG(ERROR) << remill::LLVMThingToString(src) << " < src is\n";
  LOG(ERROR) << remill::LLVMThingToString(src->getType()) << "< dest type\n";
  LOG(ERROR) << src->getType()->isStructTy() << " < is struct ty? \n";
  LOG(ERROR) << src->getType()->isVectorTy() << " < is vector ty? \n";
  LOG(ERROR) << src->getType()->isPointerTy() << " < is pointer ty?\n";


  // TODO (Carson), handling structs could be tricky....
  if (gep->getType()->isStructTy()) {
    return {gep, false};
  }
  auto src_element_type = llvm::PointerType::get(gep->getSourceElementType(),
                                                 gep->getPointerAddressSpace());

  //  auto gep_element_type = llvm::PointerType::get(gep->getResultElementType(),
  //                                                 gep->getPointerAddressSpace());
  //  auto inferred_element_type =
  //      llvm::PointerType::get(inferred_type->getPointerElementType(),
  //                             inferred_type->getPointerAddressSpace());

  llvm::SmallVector<llvm::Value *, 4> indices;
  for (auto it = gep->idx_begin(); it != gep->idx_end(); ++it) {
    indices.push_back(it->get());
  }
  // If the last index isn't a constant then we can't peel it off.
  auto last_index = llvm::dyn_cast<llvm::ConstantInt>(indices.pop_back_val());
  if (!last_index) {
    return {gep, false};
  }

  // Figure out what the last index was represented in terms of a byte offset.
  // We need to be careful about negative indices -- we want to maintain them,
  // but we don't want division/remainder to produce different roundings.
  const auto gep_elem_type_size =
      dl.getTypeAllocSize(gep->getType()->getPointerElementType())
          .getFixedSize();
  const auto inferred_ele_type_size =
      dl.getTypeAllocSize(inferred_type->getPointerElementType())
          .getFixedSize();
  const auto last_index_i = last_index->getSExtValue();
  const auto index_value =
      std::abs(last_index_i) * static_cast<uint64_t>(gep_elem_type_size);
  const auto last_index_sign = (last_index_i) ? 1 : -1;

  // Error case, in the case our inferred type size is greater than the offset
  // Lets not break anything. dont do it.
  // imagine you have an i8* with offset 1 byte, and a cast to i32*, you can't
  // represent that 1 byte with a complete index
  // If you can think it, its an edge case :galaxy_brain:
  if (inferred_ele_type_size > index_value) {
    return {gep, false};
  }

  // last_index_i = value / gep_elem_type_size
  // value = last_index_i * gep_elem_type_size
  // adjusted_value = value / inferred_type_size
  auto size_adjusted_index = index_value / inferred_ele_type_size;

  LOG(ERROR) << "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
  LOG(ERROR) << "gep elem type size (bytes): " << gep_elem_type_size << "\n";
  LOG(ERROR) << "inferred elem type size (bytes): " << inferred_ele_type_size
             << "\n";
  LOG(ERROR) << "last_index of this GEP (as gep type): " << last_index_i
             << "\n";
  LOG(ERROR) << "last_index actual value(bits) : " << index_value << "\n";
  LOG(ERROR) << "last_index of this GEP (as inferred_type): "
             << size_adjusted_index << "\n";
  LOG(ERROR) << "last_index element sign : " << last_index_sign << "\n";

  // LOG(ERROR) << "Size adjusted index (for whatever the new type is): "
  //            << size_adjusted_index << "=" <<  / "gep_elem_type_size\n";
  // The last index does not evenly divide the size of the result
  // element type.
  if ((index_value % inferred_ele_type_size)) {
    return {gep, false};
  }
  llvm::Value *new_src = nullptr;

  // Generate a new `src` that has one less index.
  if (indices.empty()) {
    new_src = src;
  } else {
    llvm::IRBuilder<> ir(gep);

    // TODO (Carson) seems kinda sketchy.
    LOG(ERROR) << "Unfolding GEP, making new gep with less indexes\n";
    LOG(ERROR) << " Source element type: "
               << remill::LLVMThingToString(src_element_type) << "\n";
    LOG(ERROR) << " Source type: " << remill::LLVMThingToString(src->getType())
               << "\n";
    LOG(ERROR) << " Source: " << remill::LLVMThingToString(src) << "\n";
    new_src =
        ir.CreateGEP(src->getType()->getPointerElementType(), src, indices);
  }
  llvm::Instruction *new_src_inst = llvm::dyn_cast<llvm::Instruction>(new_src);
  CHECK(new_src_inst != nullptr);

  // Convert that new `src` to have the correct type.
  auto [casted_src, promoted] = visitInferInst(new_src_inst, inferred_type);
  if (!promoted) {
    LOG(ERROR) << "Failed to flatten gep, making bitcast!\n";

    // TODO (Carson) check
    llvm::IRBuilder<> ir(gep);
    casted_src = ir.CreateBitCast(new_src, inferred_type);
  }
  // Now that we have `src` casted to the corrected type, we can index into
  // it, using an index that is scaled to the size of the
  indices.clear();
  indices.push_back(llvm::ConstantInt::get(
      last_index->getType(), last_index_sign * size_adjusted_index, true));
  llvm::IRBuilder<> ir(gep);

  // Casted source should be inferred_type, so get the element type
  const auto new_gep =
      ir.CreateGEP(inferred_type->getPointerElementType(), casted_src, indices);
  LOG(ERROR) << remill::LLVMThingToString(new_gep) << " Have a new gep!\n";
  return {new_gep, true};
}

// TODO (Carson), create example where promotion to operand succeeds, BUT
// for whatever reason, GEP fails.
// TODO (Carson),
// 1. if inferred type, we want to either flatten or not flattern.
// 2. Determine if flatten based on if every value is constant/can be updated.
//  a. If all constant, then go try and promote the source type.
//    x. if works, then just update each constant with new size info.
//    y. if not, push a bitcast before the gep, and update types anyway.
//  b. if not, then split the gep into parts before the val
//    x. try and promote source type.
//      i. if works, update last
std::pair<llvm::Value *, bool>
PointerLifter::visitGetElementPtrInst(llvm::GetElementPtrInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }

  auto [flat_gep, worked] = BrightenGEP_PeelLastIndex(&inst, inferred_type);
  if (worked) {
    return {flat_gep, worked};
  }
  return {&inst, false};
}
/*
inttoptr instructions indicate there are pointers. There are two cases:
1. %X = inttoptr i32 255 to i32*

%y = i32 4193555
%A = add %y, 4
2. %X = inttoptr i32 %A to i32*

In the first case, only %X is a pointer, this should already be known by the
compiler

In the second case, it indicates that %Y although of type integer, has been a
pointer
*/
std::pair<llvm::Value *, bool>
PointerLifter::visitIntToPtrInst(llvm::IntToPtrInst &inst) {

  const auto inferred_type = llvm::dyn_cast<llvm::PointerType>(inst.getType());
  auto [p, lifted_xref] =
      visitPossibleCrossReference(inst, inst.getOperandUse(0), inferred_type);

  if (auto ip = llvm::dyn_cast<llvm::Instruction>(p)) {
    LOG(ERROR) << "Visiting a pointer instruction "
               << remill::LLVMThingToString(p) << " used by "
               << remill::LLVMThingToString(&inst);

    // Propagate that type upto the original register containing the value
    // Create an entry in updated val with pointer cast.

    // If we succeded, it should be a pointer type!
    if (auto [new_ptr, changed] = visitInferInst(ip, inferred_type);
        changed && new_ptr->getType()->isPointerTy()) {
      ReplaceAllUses(&inst, new_ptr);
      return {new_ptr, true};
    }
  }

  if (lifted_xref) {
    return {p, true};
  }

  LOG(ERROR) << "Failed to promote IntToPtr inst: "
             << remill::LLVMThingToString(&inst);

  return {&inst, false};
}

std::pair<llvm::Value *, bool>
PointerLifter::visitPHINode(llvm::PHINode &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    LOG(ERROR) << "No type info for load! Returning just the phi node\n";
    return {&inst, false};
  }
  llvm::IRBuilder<> ir(&inst);

  const auto num_vals = inst.getNumIncomingValues();
  auto new_phi = ir.CreatePHI(inferred_type, num_vals);

  // We might brighten some of the phi, but not all of it.
  // We can force a success by bitcasting in case of failure.
  for (auto i = 0u; i < num_vals; i++) {
    auto incoming_val = inst.getIncomingValue(i);
    auto incoming_block = inst.getIncomingBlock(i);
    llvm::IRBuilder<> sub_ir(incoming_block->getTerminator());
    if (auto val_inst = llvm::dyn_cast<llvm::Instruction>(incoming_val)) {

      // Visit possible reference
      const auto inferred_ptr_ty = inferred_type->getPointerTo();
      auto &use = val_inst->getOperandUse(0);

      auto [p, lifted_xref] =
          visitPossibleCrossReference(*val_inst, use, inferred_ptr_ty);

      // Okay, xref lifter failed
      // Not sure what it tried/or not tried, lets try vising ourselves.
      if (!lifted_xref) {
        p = visitInferInst(val_inst, inferred_type).first;

      }
      if (p->getType() != inferred_type) {
        p = sub_ir.CreateBitOrPointerCast(p, inferred_type);
      }

      new_phi->addIncoming(p, incoming_block);
    }
    // TODO (Carson) handle const expr
    else {
      LOG(ERROR) << "Unknown type in Phi op: "
                 << remill::LLVMThingToString(incoming_val) << "\n";
      exit(1);
    }
  }
  // TODO (Carson) do we replace uses here? i dont think so.
  return {new_phi, true};
}

/*
  %4 = load i64, i64* inttoptr (i64 6295600 to i64*), align 16
  %5 = add i64 %4, 128
  %6 = inttoptr i64 %5 to i32*

  In order to collapse the inttoptr, add into a GEP, the load also needs to have
  its type promoted to a pointer

  %4 = load i32*, i32** %some_global/constant_expr, align 16
  %5 = GEP i32, %4, 32
*/
std::pair<llvm::Value *, bool>
PointerLifter::visitLoadInst(llvm::LoadInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    LOG(ERROR) << "No type info for load! Returning just the load\n";
    return {&inst, false};
  }

  // Assert that the CURRENT type of the load (in the example i64) and the new
  // promoted type (i32*) are of the same size in bytes. This prevents us from
  // accidentally truncating/extending when we don't want to
  CHECK_EQ(dl.getTypeAllocSizeInBits(inst.getType()),
           dl.getTypeAllocSizeInBits(inferred_type));

  const auto inferred_ptr_ty = inferred_type->getPointerTo();
  auto [p, lifted_xref] =
      visitPossibleCrossReference(inst, inst.getOperandUse(0), inferred_ptr_ty);

  llvm::IRBuilder<> ir(&inst);

  // If we succeeded at lifting the pointer operand as a cross-reference, then
  // promote the load.
  if (lifted_xref) {
    llvm::Value *promoted_load = ir.CreateLoad(inferred_type, p);
    ReplaceAllUses(&inst, promoted_load);
    return {promoted_load, true};
  }

  // Load operand can be another instruction.
  auto ip = llvm::dyn_cast<llvm::Instruction>(p);
  if (!ip) {
    return {&inst, false};
  }

  LOG(ERROR) << "Load operand is an instruction! "
             << remill::LLVMThingToString(ip) << "\n";

  // Load from potentially a new addr.
  auto [maybe_new_addr, loaded_addr_changed] =
      visitInferInst(ip, inferred_type->getPointerTo());
  if (!loaded_addr_changed) {
    LOG(ERROR) << "Failed to promote load! Operand type not promoted "
               << remill::LLVMThingToString(maybe_new_addr) << "\n";
    return {&inst, false};
  }

  // Create a new load instruction with type inferred_type which loads a ptr
  // to inferred_type
  LOG(ERROR) << remill::LLVMThingToString(&inst) << "< current load\n";
  LOG(ERROR) << remill::LLVMThingToString(inferred_type)
             << " < inferred type to load\n";
  LOG(ERROR) << remill::LLVMThingToString(maybe_new_addr) << " < new inst\n";
  LOG(ERROR) << remill::LLVMThingToString(maybe_new_addr->getType())
             << " < new inst type, should be * to the first\n";
  llvm::Value *promoted_load = ir.CreateLoad(inferred_type, maybe_new_addr);
  LOG(ERROR) << "new load: " << remill::LLVMThingToString(promoted_load)
             << "\n";

  ReplaceAllUses(&inst, promoted_load);
  return {promoted_load, true};
}

// Visit of use of a value `val` by the instruction `user`, where we
// believe this use should be a pointer to the type `inferred_value_type`.
std::pair<llvm::Value *, bool> PointerLifter::visitPossibleCrossReference(
    llvm::Instruction &user, llvm::Use &use, llvm::PointerType *inferred_type) {

  const auto val = use.get();
  auto new_val = val;
  const auto ra = xref_resolver.TryResolveReference(val);
  auto changed = false;

  // Not much we can do about the return address reference, and the stack
  // pointer reference should get replaced by the stack frame recovery pass.
  if (ra.references_return_address || ra.references_stack_pointer) {
    if (inferred_type) {
      new_val = ConvertToPointer(&user, val, inferred_type);
      changed = new_val != val;
    }

  } else if (!ra.is_valid) {

    // If it's a constant expression and the xref resolver failed then we'll
    // unroll it into an instruction and recursively drill down on it.
    if (const auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
      auto ce_inst = ce->getAsInstruction();
      ce_inst->insertBefore(&user);
      use.set(ce_inst);
      if (inferred_type) {
        new_val = visitInferInst(ce_inst, inferred_type).first;
        new_val = ConvertToPointer(ce_inst, new_val, inferred_type);
        changed = true;

      } else {
        new_val = ce_inst;

        // NOTE(pag): We don't mark `changed = true`.
      }
    }

  // More strong hints of stuff being reference, but in this case, we don't
  // have the benefit of an inferred pointer type.
  } else if (ra.references_global_value || ra.references_entity ||
             ra.references_program_counter) {
    if (inferred_type) {
      new_val = value_lifter.Lift(ra.u.address, inferred_type);
      changed = true;

    // We weren't given an inferred type from the usage of the code, but
    // we did find that the resolved address is related to `hinted_value_type`.
    // One trickiness with this is that we might be displaced from
    // `hinted_value_type`.
    } else if (ra.hinted_value_type) {
      if (0 < ra.displacement_from_hinted_value_type) {
        auto disp =
            static_cast<uint64_t>(ra.displacement_from_hinted_value_type);

        if (ra.u.address > disp) {
          auto base_val = value_lifter.Lift(
              ra.u.address - disp, ra.hinted_value_type->getPointerTo(0));

          // auto val_size = dl.getTypeAllocSize(ra.hinted_value_type).getFixedSize();
          // auto offset = val_size % disp;
          // new_val = remill::BuildPointerToOffset(ir, ptr, dest_elem_offset, dest_ptr_type);
          // changed = true;
          LOG(ERROR) << "TODO: Handle displacements from value type in "
                     << remill::LLVMThingToString(val) << "; value type is "
                     << remill::LLVMThingToString(ra.hinted_value_type)
                     << "; resolved address is " << std::hex << ra.u.address
                     << std::dec << "; displacement is "
                     << ra.displacement_from_hinted_value_type
                     << "; base value is "
                     << remill::LLVMThingToString(base_val);

          // TODO(pag): Figure out the type to pass to `BuildPointerToOffset`.

        // A displacement that's bigger than our resolved address. This is
        // probably a bug in the cross-reference resolver, or some weird
        // integer overflow.
        //
        // NOTE(pag): This probably isn't worth handling until we hit it, hence
        //            the `FATAL` log to tell us loud and clear.
        } else {
          LOG(FATAL) << "TODO: Handle too-big displacements from value type in "
                     << remill::LLVMThingToString(val) << "; value type is "
                     << remill::LLVMThingToString(ra.hinted_value_type)
                     << "; resolved address is " << std::hex << ra.u.address
                     << std::dec << "; displacement is "
                     << ra.displacement_from_hinted_value_type;
        }

      // Negative displacement, this is a bit odd.
      //
      // NOTE(pag): This probably isn't worth handling until we hit it, hence
      //            the `FATAL` log to tell us loud and clear.
      } else if (0 > ra.displacement_from_hinted_value_type) {
        LOG(FATAL) << "TODO: Handle negatived displacements from value type in "
                   << remill::LLVMThingToString(val) << "; value type is "
                   << remill::LLVMThingToString(ra.hinted_value_type)
                   << "; resolved address is " << std::hex << ra.u.address
                   << std::dec << "; displacement is "
                   << ra.displacement_from_hinted_value_type;

      // The displacement is zero, so we have a pointer type.
      } else {
        new_val = value_lifter.Lift(ra.u.address,
                                    ra.hinted_value_type->getPointerTo(0));
        changed = true;
      }

    } else {
      LOG(ERROR) << "Found address " << std::hex << ra.u.address << std::dec
                 << " derived from " << remill::LLVMThingToString(val)
                 << " that seems like an address " << ra.references_global_value
                 << ra.references_entity << ra.references_program_counter;
    }

  // OK, we resolved to an actual address, and we have a pointer type; this is
  // a powerful hint that the `ra.u.address` is an entity that we want a
  // a reference for. Still, it could be that we're dealing with something
  // like the `4` in `%bar = add %foo, 4`, where the inferred pointer type
  // of `4` is coming from a usage of `%bar`.
  } else if (inferred_type) {
    auto lifted = value_lifter.Lift(ra.u.address, inferred_type);
    if (llvm::isa<llvm::GlobalValue>(lifted)) {
      new_val = lifted;
      changed = true;

    // This is basically the case of the `4` in the `add` above.
    } else {
      LOG(ERROR)
          << "Found address " << std::hex << ra.u.address << std::dec
          << " derived from " << remill::LLVMThingToString(val)
          << " that has an inferred pointer type but isn't associated with"
          << " any entities";
    }

  } else {
    DLOG(ERROR) << "Ignoring value " << std::hex << ra.u.address << std::dec
                << " derived from " << remill::LLVMThingToString(val)
                << " that doesn't seem like an address";
  }

  return {new_val, changed};
}

/*
Binary operators such as add, sub, mul, etc

Ultimately we want to eliminate the operation and replace it with a GEP when we
can, or just cast the result if is needed.

Here is an example with an add.

Original:
%A = i32 419444 <--- See that %A is an i32, create a new pointer for this.
%B = i32 add %A 8 <- See that %B is an add, Visit the instruction %A
%C = inttoptr %B <-- Infer that %B is really a pointer. Visit %B
---------------------^ Start

Intermediate
%A = i32 419444
%A_PTR = i32* 41944 <-- Create a new ptr type, Mark updated vals as A ---> A_PTR
%B = i32 add %A 8
%C = inttoptr %B

Intermediate 2
%A = i32 419444
%A_PTR = i32* 41944
%B = i32 add %A 8
%B_GEP = i32* GEP %A_PTR, <indexes> <--- Visit returns with the new A_PTR,
                                         Create a GEP, B ---> B_GEP
%C = inttoptr %B

Intermediate 3
%A = i32 419444
%A_PTR = i32* 41944
%B = i32 add %A 8
%B_GEP = i32* GEP %A_PTR, <indexes>
%C = inttoptr %B  <--- Update uses of C --> B_GEP.

Then later when uses are actually replaced
(A-->A_PTR), (B-->B_GEP), (C-->B_GEP)

Old instructions are erased

%A_PTR = i32* 41944
%B_GEP = i32* GEP %A_PTR <indexes>

*/
std::pair<llvm::Value *, bool>
PointerLifter::visitBinaryOperator(llvm::BinaryOperator &inst) {

  // Adds by themselves do not infer pointer info
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }

  const auto inferred_type_as_ptr =
      llvm::dyn_cast<llvm::PointerType>(inferred_type);

  // If we are coming from downstream, then we have an inferred type.
  const auto lhs_op = visitPossibleCrossReference(inst, inst.getOperandUse(0),
                                                  inferred_type_as_ptr)
                          .first;

  const auto rhs_op = visitPossibleCrossReference(inst, inst.getOperandUse(1),
                                                  inferred_type_as_ptr)
                          .first;

  auto lhs_ptr = lhs_op->getType()->isPointerTy();
  auto rhs_ptr = rhs_op->getType()->isPointerTy();

  // In the original GetPointer code, there is a case that logs an error
  // When both addresses are pointers, because its weird, and I'm not sure
  // why that would be
  if (lhs_ptr && rhs_ptr) {
    llvm::IRBuilder ir(inst.getNextNode());
    const auto bb = ir.GetInsertBlock();

    LOG(ERROR) << "Two pointers " << remill::LLVMThingToString(lhs_op)
               << " and " << remill::LLVMThingToString(rhs_op)
               << " are added together " << remill::LLVMThingToString(&inst)
               << " in block " << bb->getName().str() << " in function "
               << bb->getParent()->getName().str();

    llvm::Value *new_pointer = ir.CreateIntToPtr(&inst, inferred_type);
    ReplaceAllUses(&inst, new_pointer);
    return {new_pointer, true};

  // If neither of them are known pointers, then we have some inference to
  // propagate!
  } else if (!lhs_ptr && !rhs_ptr) {
    auto lhs_inst = llvm::dyn_cast<llvm::Instruction>(lhs_op);
    auto rhs_inst = llvm::dyn_cast<llvm::Instruction>(rhs_op);
    if (lhs_inst) {

      // visit it! propagate type information.
      auto [ptr_val, changed] = visitInferInst(lhs_inst, inferred_type);
      if (!changed) {
        return {&inst, false};
      }
      if (!ptr_val->getType()->isPointerTy()) {
        LOG(ERROR) << "Error! return type is not a pointer: "
                   << remill::LLVMThingToString(ptr_val);

        // Default behavior is just to cast, this is not ideal, because
        // we want to try and propagate as much as we can.
        llvm::IRBuilder ir(inst.getNextNode());
        llvm::Value *default_cast = ir.CreateBitCast(&inst, inferred_type);

        // ReplaceAllUses(&inst, default_cast);
        return {default_cast, true};
      }

      CHECK_EQ(ptr_val->getType()->isPointerTy(), 1);

      // ^ should be in updated vals. Next create an indexed pointer
      // This could be a GEP, but in some cases might just be a bitcast.
      auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(rhs_op);

      // CHECK_NE(rhs_const, nullptr);
      // CHECK_EQ(rhs_inst, nullptr);

      // TODO (Carson) Sanity check this, but the return value from
      // visitInferInst. Could be a constant pointer, or an instruction. Where
      // should the insert point be? Create the GEP/Indexed pointer
      llvm::IRBuilder ir(lhs_inst);
      llvm::Value *indexed_pointer =
          GetIndexedPointer(ir, ptr_val, rhs_const, inferred_type);

      // Mark as updated
      ReplaceAllUses(&inst, indexed_pointer);
      return {indexed_pointer, true};

    // Same but for RHS
    } else if (rhs_inst) {
      auto [ptr_val, changed] = visitInferInst(rhs_inst, inferred_type);
      if (!changed) {
        return {&inst, false};
      }

      // TODO (Carson) Confirm pointer type.
      auto lhs_const = llvm::dyn_cast<llvm::ConstantInt>(lhs_op);

      // CHECK_NE(lhs_const, nullptr);
      // CHECK_EQ(lhs_inst, nullptr);
      llvm::IRBuilder ir(rhs_inst);
      llvm::Value *indexed_pointer =
          GetIndexedPointer(ir, ptr_val, lhs_const, inferred_type);
      ReplaceAllUses(&inst, indexed_pointer);
      return {indexed_pointer, true};

    // We know there is some pointer info, but they are both consts?
    } else {

      // We don't have a L/RHS instruction, just create a pointer
      llvm::IRBuilder ir(inst.getNextNode());
      llvm::Value *add_ptr = ir.CreateIntToPtr(&inst, inferred_type);

      // ReplaceAllUses(&inst, add_ptr);
      return {add_ptr, true};
    }

  // The left-hand side is a pointer!
  } else if (lhs_ptr) {

    LOG(ERROR) << remill::LLVMThingToString(&inst) << "\n"
               << remill::LLVMThingToString(lhs_op) << "\n"
               << remill::LLVMThingToString(rhs_op);
    return {&inst, false};

  // The right-hand side is a pointer!
  } else {
    CHECK(rhs_ptr);

    LOG(ERROR) << remill::LLVMThingToString(&inst) << "\n"
               << remill::LLVMThingToString(lhs_op) << "\n"
               << remill::LLVMThingToString(rhs_op);
    return {&inst, false};
  }
}
/*
This is the driver code for the pointer lifter

It creates a worklist out of the instructions in the original function and
visits them. In order to do downstream pointer propagation, additional uses of
updated values are added into the next_worklist. Pointer lifting for a function
is done when we reach a fixed point, when the next_worklist is empty.
*/

// If the inferred type of this GEP isn't the same as its current type, then
// we might be in the following situation:
//
//      define i64 @valid_test(i64* %0) local_unnamed_addr #1 {
//        %2 = bitcast i64* %0 to i8**
//        %3 = load i8*, i8** %2, align 8
//        %4 = getelementptr i8, i8* %3, i64 36   <-- we're here
//        %5 = bitcast i8* %4 to i32*             <-- inferred_type from here
//        %6 = load i32, i32* %5, align 4
//        %7 = zext i32 %6 to i64
//        ret i64 %7
//      }
//
// What we want to do is convert this GEP into something that is more
// amenable to the bitcasted type. We'll try to peel off the last index,
// bitcast the src absent this index, then adjust, and push the bitcast down.
//
//
//      ; Function Attrs: noinline
//      define i64 @valid_test(i32** %0) local_unnamed_addr #1 {
//        %2 = bitcast i64* %0 to i8**
//        %3 = load i8*, i8** %2, align 8
//        %4 = bitcast i8* %3 to i32*             <-- Pushed down bitcast
//        %5 = getelementptr i32, i32* %4, i32 9  <-- Peeled index
//        %6 = load i32, i32* %4, align 4
//        %7 = zext i32 %6 to i64
//        ret i64 %7
//      }
//
// Then we rely on the bitcast for pushing through.
/*
llvm::Value *PointerLifter::BrightenGEP_PeelLastIndex(
      llvm::IRBuilder<> &ir, llvm::GEPOperator *gep,
      llvm::PointerType *inferred_type) {
  auto src = gep->getPointerOperand();
  auto src_type = llvm::PointerType::get(gep->getSourceElementType(),
                                         gep->getPointerAddressSpace());
  auto gep_type = llvm::PointerType::get(gep->getResultElementType(),
                                         gep->getPointerAddressSpace());
  llvm::SmallVector<llvm::Value *, 4> indices;
  for (auto it = gep->idx_begin(); it != gep->idx_end(); ++it) {
    indices.push_back(it->get());
  }
  // If the last index isn't a constant then we can't peel it off.
  auto last_index = llvm::dyn_cast<llvm::ConstantInt>(indices.pop_back_val());
  if (!last_index) {
    return nullptr;
  }
  // Figure out what the last index was represented in terms of a byte offset.
  // We need to be careful about negative indices -- we want to maintain them,
  // but we don't want division/remainder to produce different roundings.
  const auto gep_elem_type_size =
      dl->getTypeAllocSize(gep->getResultElementType()).getFixedSize();
  const auto last_index_i = last_index->getSExtValue() *
                            static_cast<int64_t>(gep_elem_type_size);
  const auto last_index_ai = std::abs(last_index_i);
  const auto last_index_sign = (last_index_i / std::max(last_index_ai, 1ll));
  auto elem_size = static_cast<int64_t>(
      dl->getTypeAllocSize(gep->getResultElementType()).getFixedSize());

  // The last index does not evenly divide the size of the result
  // element type.
  if ((last_index_ai % elem_size)) {
    return nullptr;
  }
  llvm::Value *new_src = nullptr;

  // Generate a new `src` that has one less index.
  if (indices.empty()) {
    new_src = src;
  } else {
    new_src = ir.CreateGEP(src_type, src, indices);
  }
  // Convert that new `src` to have the correct type.
  auto casted_src = Brighten(ir, new_src, inferred_type);
  if (!casted_src) {
    casted_src = ir.CreateBitCast(new_src, inferred_type);
  }
  MergeEquivalenceClasses(new_src, casted_src);

  // Now that we have `src` casted to the corrected type, we can index into
  // it, using an index that is scaled to the size of the
  indices.clear();
  indices.push_back(llvm::ConstantInt::get(
      last_index->getType(),
      last_index_sign * (last_index_ai / elem_size), true));
  const auto new_gep = ir.CreateGEP(inferred_type, casted_src, indices);
  MergeEquivalenceClasses(gep, new_gep);
  return new_gep;
}
llvm::Value *PointerLifter::BrightenGEP(
    llvm::IRBuilder<> &ir, llvm::GEPOperator *gep,
    llvm::PointerType *inferred_type) {
  auto src = gep->getPointerOperand();
  auto src_type = llvm::PointerType::get(gep->getSourceElementType(),
                                         gep->getPointerAddressSpace());
  auto gep_type = llvm::PointerType::get(gep->getResultElementType(),
                                         gep->getPointerAddressSpace());
  auto goal_src_type = src_type;

  llvm::SmallVector<llvm::Value *, 4> indices;
  if (inferred_type != gep_type) {
    if (auto new_gep = BrightenGEP_PeelLastIndex(ir, gep, inferred_type)) {
      return new_gep;
    }
    // Worst-case: bitcast.
    auto new_gep = ir.CreateBitCast(gep, inferred_type);
    MergeEquivalenceClasses(gep, new_gep);
    return new_gep;
  } else {
  }
  // Top-down, try to brighten `src` into `src` type.
  if (auto new_src = Brighten(ir, src, src_type);
      new_src && new_src != src) {
    src = new_src;
    src_type = goal_src_type;
  }
  // If the source operand isn't a GEP then there's not much else to do.
  auto src_gep = llvm::dyn_cast<llvm::GEPOperator>(src);
  if (!src_gep) {
    return nullptr;
  }
  indices.clear();
  for (auto it = src_gep->idx_begin(); it != src_gep->idx_end(); ++it) {
    indices.push_back(it->get());
  }
  // Merge by adding trailing indices of GEP.
  if (src_type == gep_type) {
    if (gep->getNumIndices() == 1) {
      indices.back() = ir.CreateAdd(indices.back(), gep->getOperand(1));
      auto new_gep = ir.CreateGEP(src_type, src, indices);
      MergeEquivalenceClasses(gep, new_gep);
      return new_gep;
    } else {
      LOG(ERROR)
          << "Unable to combine " << remill::LLVMThingToString(src)
          << " with " << remill::LLVMThingToString(gep);
      return nullptr;
    }
// Merge by extending indices of GEP. We need to make sure to combine the
// last index of our `src` GEP with the first index of our `gep`.
  } else {
    auto it = gep->idx_begin();
    indices.push_back(ir.CreateAdd(indices.pop_back_val(), it->get()));
    while (++it != gep->idx_end()) {
      indices.push_back(it->get());
    }
    auto new_gep = ir.CreateGEP(src_type, src, indices);
    MergeEquivalenceClasses(gep, new_gep);
    ReplaceAllUses(gep, new_gep);
    return new_gep;
  }
}
*/
void PointerLifter::LiftFunction(llvm::Function &func) {
  std::vector<llvm::Instruction *> worklist;

  made_progress = true;
  for (auto i = 0u; i < max_gas && made_progress; ++i) {
    made_progress = false;

    //    func.print(llvm::errs(), nullptr);
    for (auto &block : func) {
      for (auto &inst : block) {
        worklist.push_back(&inst);
      }
    }

    for (auto inst : worklist) {
      visit(inst);
    }

    // Note (For Peter): The reason we are doing deletion here instead of the
    // end, is that if we don't we keep iterating over what should be dead code,
    // and then we would have to keep track of instructions we have seen before,
    // but depending on changes we make, instructions we have seen before might
    // need to be updated anyway... it gets messy. Removing dead code at the end
    // of each iteration guarantees convergence
    for (auto &inst : to_remove) {
      if (auto rep_inst = rep_map[inst];
          rep_inst && rep_inst->getType() == inst->getType()) {
        inst->replaceAllUsesWith(rep_inst);
        inst->eraseFromParent();
      }
    }
    to_remove.clear();

    llvm::legacy::FunctionPassManager fpm(mod);
    fpm.add(llvm::createDeadCodeEliminationPass());
    fpm.add(llvm::createDeadInstEliminationPass());
    fpm.doInitialization();
    fpm.run(func);
    fpm.doFinalization();

    worklist.clear();
  }
}

// Anvill-lifted bitcode operates at a very low level, swapping between integer
// and pointer representations. It is typically for just-lifted bitcode to
// perform integer arithmetic on addresses, then cast those integers into
// pointers in order to do a `load` or `store`. This happens because the bitcode
// we get from Remill uses memory access intrinsics, which abstract over the
// target program's address space and model memory loads/stores in terms of
// intrinsic function calls operating on integer addresses. When these intrinsic
// calls are lowered into `load` and `store` instructions by
// `LowerRemillMemoryAccessIntrinsics`, we are left with a mixed bag in integer
// arithmetic and then `inttoptr` casts.
//
// Ideally, we want to comprehensively brighten all integer operations that
// produce pointers into pointer operations. For example, integer arithmetic
// should instead become `getelementptr` instructions, where possible, which
// model pointer arithmetic at a higher level.
//
// This function attempts to apply a battery of pattern-based transforms to
// brighten integer operations into pointer operations.
llvm::FunctionPass *CreateBrightenPointerOperations(const EntityLifter &lifter, const ValueLifter &value_lifter, const CrossReferenceResolver& xref_res,
                                                    unsigned max_gas) {
  return new PointerLifterPass(lifter, value_lifter, xref_res, max_gas ? max_gas : 250u);
}

}  // namespace anvill
