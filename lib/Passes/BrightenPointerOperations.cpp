/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "BrightenPointerOperations.h"

#include <anvill/Transforms.h>
#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Util.h>

#include "Utils.h"

namespace anvill {

char PointerLifterPass::ID = '\0';

PointerLifterPass::PointerLifterPass(unsigned max_gas_) : max_gas(max_gas_) {}

llvm::PreservedAnalyses
PointerLifterPass::run(llvm::Function &f, llvm::FunctionAnalysisManager &AM) {

  // f.print(llvm::errs(), nullptr);
  PointerLifter lifter(&f, max_gas);
  lifter.LiftFunction(f);

  // f.print(llvm::errs(), nullptr);
  // TODO (Carson) have an analysis function which determines modifications
  // Then use lift function to run those modifications
  // Can return true/false depending on what was modified
  return llvm::PreservedAnalyses::none();
}

PointerLifter::PointerLifter(llvm::Function *func_, unsigned max_gas_)
    : max_gas(max_gas_),
      func(func_),
      mod(func->getParent()),
      context(mod->getContext()),
      i32_ty(llvm::Type::getInt32Ty(context)),
      i8_ty(llvm::Type::getInt8Ty(context)),
      i8_ptr_ty(i8_ty->getPointerTo()),
      dl(mod->getDataLayout()) {}

// Creates a cast of val to a dest type.
// This casts whatever value we want to a pointer, propagating the information
llvm::Value *PointerLifter::getPointerToValue(llvm::IRBuilder<> &ir,
                                              llvm::Value *val,
                                              llvm::Type *dest_type) {

  // is the value another instruction? Visit it

  llvm::Value *ptr_cast = ir.CreateBitOrPointerCast(val, dest_type);
  return ptr_cast;
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
      if (!first_ret || ret.first->getType() == inferred_type) {
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
    return {first_ret, changed && first_ret->getType() == inferred_type};

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
    const auto rhs_index = static_cast<int32_t>(rhs_const->getSExtValue());

    const auto [new_lhs, index] =
        remill::StripAndAccumulateConstantOffsets(dl, address);

    llvm::GlobalVariable *lhs_global =
        llvm::dyn_cast<llvm::GlobalVariable>(new_lhs);

    if (lhs_global) {

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
          ptr = ir.CreateGEP(lhs_elem_type, address, indices);
        }
      } else {
        const auto pos_rhs_index = static_cast<unsigned>(rhs_index);
        if (!(pos_rhs_index % lhs_el_size)) {
          const auto scaled_index = static_cast<uint64_t>(
              rhs_index / static_cast<int64_t>(lhs_el_size));
          llvm::Value *indices[1] = {
              llvm::ConstantInt::get(i32_ty, scaled_index, false)};
          ptr = ir.CreateGEP(lhs_elem_type, address, indices);
        }
      }
    }

    // We got a GEP for the dest, now make sure it's the right type.
    if (ptr) {
      if (address->getType() == dest_type) {
        return ptr;
      } else {
        llvm::Value *b1 = ir.CreateBitCast(ptr, dest_type);
        return b1;
      }
    }
  }
  auto base = ir.CreateBitCast(address, i8_ptr_ty);
  llvm::Value *indices[1] = {ir.CreateTrunc(offset, i32_ty)};
  auto gep = ir.CreateGEP(i8_ty, base, indices);
  llvm::Value *b3 = ir.CreateBitCast(gep, dest_type);
  return b3;
}

// MUST have an implementation of this if llvm:InstVisitor retun type is not
// void.
std::pair<llvm::Value *, bool>
PointerLifter::visitInstruction(llvm::Instruction &inst) {
  return {&inst, false};
}

void PointerLifter::ReplaceAllUses(llvm::Value *old_val, llvm::Value *new_val) {
  CopyMetadataTo(old_val, new_val);
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

    // ReplaceAllUses(&inst, new_bitcast);
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
      if (new_var_type->getType() == inst.getType()) {
        ReplaceAllUses(&inst, new_var_type);
      }
      return {new_var_type, true};
    }
    //    DLOG(WARNING) << "Bitcast: Failed to propagate info with pointer_inst: "
    //                  << remill::LLVMThingToString(pointer_inst) << "\n";
    return {&inst, false};
  }
  // TODO (Carson) make sure in the visitor methods that we dont assume inferred
  // type is the return type, we can fail!
  //  DLOG(WARNING) << "BitCast, unknown operand type: "
  //                << remill::LLVMThingToString(inst.getOperand(0)->getType());
  return {&inst, false};
}

// Use this to flatten a gep
// Replace all uses of the original gep with the return value (final flattened)
// Remove spurious instructions with dead code removal.
llvm::Value *PointerLifter::flattenGEP(llvm::GetElementPtrInst *gep) {

  // FIXME (Carson), delete once we can fix the TODO with getting indexed types
  // Ticket #195
  if (gep->getPointerOperandType()->getPointerElementType()->isStructTy() ||
      gep->getPointerOperandType()->getPointerElementType()->isVectorTy()) {
    return gep;
  }
  if (gep->getSourceElementType()->isVectorTy() ||
      gep->getSourceElementType()->isStructTy()) {
    return gep;
  }
  if (gep->getSourceElementType()->isArrayTy()) {
    return gep;
  }

  // gep a b c d, to:
  // 0 = gep a b c
  // gep 0 d, etc, etc until its all flat.
  llvm::SmallVector<llvm::Value *, 4> indices;
  for (auto it = gep->idx_begin(); it != gep->idx_end(); ++it) {
    indices.push_back(it->get());
  }
  if (indices.size() <= 1) {
    return gep;
  }
  // If its not 1, we recurse and flatten
  auto last_index = indices.pop_back_val();

  // Make non flat version.
  llvm::IRBuilder<> ir(gep);
  llvm::Value *base_ptr = gep->getPointerOperand();
  llvm::Value *non_flat_val;

  // TODO (Carson) - THESE GEPS need to be the type at indexes - 1.
  if (gep->isInBounds()) {
    non_flat_val = ir.CreateInBoundsGEP(base_ptr, indices);
  } else {
    non_flat_val = ir.CreateGEP(base_ptr, indices);
  }
  llvm::GetElementPtrInst *non_flat_gep =
      llvm::dyn_cast<llvm::GetElementPtrInst>(non_flat_val);
  CHECK(non_flat_gep != nullptr);
  auto base_gep = flattenGEP(non_flat_gep);
  llvm::Value *flat_gep;

  // These should be the same as the type that was passed in.
  if (gep->isInBounds()) {
    flat_gep = ir.CreateInBoundsGEP(gep->getType(), base_gep, last_index);
  } else {
    flat_gep = ir.CreateGEP(gep->getType(), base_gep, last_index);
  }
  return flat_gep;
}

// TODO (Carson) maybe change back to pointer type.
// TODO (Carson) gep is not a good name for this shenanigans
std::pair<llvm::Value *, bool>
PointerLifter::BrightenGEP_PeelLastIndex(llvm::GetElementPtrInst *gep,
                                         llvm::Type *inferred_type) {
  return {gep, false};

  // TODO (Carson) refactor this to use canRewriteGEP

  if (gep->getType()->isPointerTy()) {
    if (gep->getType()->getPointerElementType()->isStructTy()) {
      return {gep, false};
    }
  }
  auto src = gep->getPointerOperand();

  // TODO (Carson), handling structs could be tricky....
  if (gep->getType()->isStructTy()) {
    return {gep, false};
  }

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
    new_src =
        ir.CreateGEP(src->getType()->getPointerElementType(), src, indices);
  }
  llvm::Instruction *new_src_inst = llvm::dyn_cast<llvm::Instruction>(new_src);
  if (!new_src_inst) {
    return {gep, false};  // E.g. could be an `llvm::Argument *`.
  }

  // Convert that new `src` to have the correct type.
  auto [casted_src, promoted] = visitInferInst(new_src_inst, inferred_type);
  if (!promoted) {

    //    DLOG(INFO) << "Failed to flatten gep, making bitcast!\n";

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

  // TODO (Carson) remove these when we can handle them.
  if (inst.getSourceElementType()->isStructTy() ||
      inst.getSourceElementType()->isVectorTy() ||
      inst.getSourceElementType()->isArrayTy()) {
    return {&inst, false};
  }
  auto [flat_gep, worked] = BrightenGEP_PeelLastIndex(&inst, inferred_type);
  if (worked) {
    ReplaceAllUses(&inst, flat_gep);
    return {flat_gep, worked};
  }
  return {&inst, false};
}

std::pair<llvm::Value *, bool>
PointerLifter::visitPtrToIntInst(llvm::PtrToIntInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }
  // If we have an inferred type, it means the result of the ptrtoint
  // was once again casted to be a pointer, maybe of a different type.
  // Try and propagate if possible

  if (auto ptr_inst = llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0))) {
    auto [new_ptr, worked] = visitInferInst(ptr_inst, inferred_type);
    if (worked) {
      return {new_ptr, worked};
    }


    // If its a constant expr/argument/whatever, if its types match return it.
  } else if (auto operand = inst.getOperand(0)) {
    if (operand->getType() == inferred_type) {
      return {operand, true};
    }
  }

  // If it's not the same type, cast.
  llvm::IRBuilder<> ir(&inst);
  auto ptr_val = inst.getOperand(0);
  llvm::Value *cast = ir.CreateBitOrPointerCast(ptr_val, inferred_type);
  return {cast, true};
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
  llvm::Type *inferred_type = inst.getType();
  if (auto ptr_inst = llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0))) {
    auto [new_val, worked] = visitInferInst(ptr_inst, inferred_type);
    if (!worked) {
      return {&inst, false};
    }
    ReplaceAllUses(&inst, new_val);
    return {new_val, true};
  }
  return {&inst, false};
}

std::pair<llvm::Value *, bool>
PointerLifter::visitPHINode(llvm::PHINode &inst) {

  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {

    //    DLOG(WARNING) << "No type info for load! Returning just the phi node\n";
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
    if (auto val_inst = llvm::dyn_cast<llvm::Instruction>(incoming_val)) {

      // Visit possible reference
      auto [new_inst, worked] = visitInferInst(val_inst, inferred_type);

      // If failed, force a success
      if (!worked) {

        // Returning false here, forcing a success created new inttoptr's which created new loops
        // Returning false, yes we would have maybe made some new instructions visiting previous phi arguments
        // but when we return false, it means that the new phi is not used, meaning that it and its WIP args will be removed
        // by dead instruction removal.
        return {&inst, false};
      }
      new_phi->addIncoming(new_inst, incoming_block);

      // TODO (Carson) handle const expr
    } else {

      //      DLOG(WARNING) << "Unknown type in Phi op: "
      //                    << remill::LLVMThingToString(incoming_val) << "\n";
      new_phi->eraseFromParent();
      return {&inst, false};
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
    return {&inst, false};
  }
  // Assert that the CURRENT type of the load (in the example i64) and the new promoted type (i32*)
  // Are of the same size in bytes.
  // This prevents us from accidentally truncating/extending when we don't want to
  auto dl = mod->getDataLayout();
  if (dl.getTypeAllocSizeInBits(inst.getType()) !=
      dl.getTypeAllocSizeInBits(inferred_type)) {
    return {&inst, false};
  }

  // Load operand can be another instruction
  if (llvm::Instruction *possible_mem_loc =
          llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0))) {

    // Load from potentially a new addr.
    auto [maybe_new_addr, changed] =
        visitInferInst(possible_mem_loc, inferred_type->getPointerTo());
    if (!changed) {

      //      DLOG(WARNING) << "Failed to promote load! Operand type not promoted "
      //                    << remill::LLVMThingToString(maybe_new_addr) << "\n";
      return {&inst, false};
    }
    // Create a new load instruction with type inferred_type which loads a ptr to inferred_type
    llvm::IRBuilder ir(&inst);
    llvm::Value *promoted_load = ir.CreateLoad(inferred_type, maybe_new_addr);
    return {promoted_load, true};
  }
  // Load operand can be a constant expression
  // NOTE This might conflict with another pass beforehand.
  /*
 if (llvm::ConstantExpr *const_expr =
         llvm::dyn_cast<llvm::ConstantExpr>(inst.getOperand(0))) {
   llvm::Instruction *expr_as_inst = const_expr->getAsInstruction();
   expr_as_inst->insertBefore(&inst);

   // Rather than passing in the inferred resulting type to this load, pass in the type that matches the load.
   auto [new_const_ptr, changed] = visitInferInst(expr_as_inst, inferred_type);

   // Here, the initial promotion failed. This could be because of any number of reasons
   // We can give up, but it might be best to actually do a "best effort" transform
   // An example is we can insert a bitcast here, and then forcibly promote the load, allowing other optimizations to continueu
   if (!changed) {
     llvm::IRBuilder ir(&inst);
     llvm::Value * ptr_cast = ir.CreateBitOrPointerCast(expr_as_inst, inferred_type->getPointerTo());
     llvm::Value * promoted_load = ir.CreateLoad(inferred_type, ptr_cast);
     return {promoted_load, true};
   }
   llvm::IRBuilder ir(&inst);
   llvm::Value *promoted_load = ir.CreateLoad(inferred_type, new_const_ptr);
   return {promoted_load, true};
 }
 */
  return {&inst, false};
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
PointerLifter::visitBinaryOperator(llvm::BinaryOperator &binop) {
  const auto inst = llvm::dyn_cast<llvm::Instruction>(&binop);
  if (!inst) {
    return {&binop, false};
  }

  switch (inst->getOpcode()) {
    case llvm::Instruction::Add:
    case llvm::Instruction::Sub: break;
    default: return {&binop, false};
  }

  llvm::Value *lhs_op = inst->getOperand(0);
  llvm::Value *rhs_op = inst->getOperand(1);

  llvm::Type *inferred_type = inferred_types[inst];
  if (!inferred_type) {

    // This looks naive but it's not
    // This is a greedy approach to handling the case where parent operands are ptrtoint instructions
    // It lets us do smaller brightening operations like turning ptrtoint... add.. into -> gep.. ptrtoint
    // Rather than recursively searching up the tree for ptrtoint, if every instruction makes the local decision
    // to brighten, then over iterations we will eventually have optimal brightening.
    llvm::PtrToIntInst *lhs_ptr = llvm::dyn_cast<llvm::PtrToIntInst>(lhs_op);
    llvm::PtrToIntInst *rhs_ptr = llvm::dyn_cast<llvm::PtrToIntInst>(rhs_op);

    // Check lhs/rhs for ptr/constant info to make a gep.
    // In this scenario we have no downstream to return to like inttoptr,
    // so we want to emit an instruction casting the gep to an int, and returning it.
    // we also want to replace uses of the add with our int cast.
    if (lhs_ptr) {
      if (auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(rhs_op)) {
        llvm::IRBuilder<> ir(inst);
        llvm::Value *indexed_pointer =
            GetIndexedPointer(ir, lhs_ptr->getOperand(0), rhs_const,
                              lhs_ptr->getOperand(0)->getType());
        llvm::Value *int_cast =
            ir.CreateBitOrPointerCast(indexed_pointer, inst->getType());
        ReplaceAllUses(inst, int_cast);
        return {int_cast, true};
      }
    }
    if (rhs_ptr) {
      if (auto lhs_const = llvm::dyn_cast<llvm::ConstantInt>(lhs_op)) {
        llvm::IRBuilder<> ir(inst);
        llvm::Value *indexed_pointer =
            GetIndexedPointer(ir, rhs_ptr->getOperand(0), lhs_const,
                              rhs_ptr->getOperand(0)->getType());
        llvm::Value *int_cast =
            ir.CreateBitOrPointerCast(indexed_pointer, inst->getType());
        ReplaceAllUses(inst, int_cast);
        return {int_cast, true};
      }
    }

    return {inst, false};
  }

  auto lhs_ptr = lhs_op->getType()->isPointerTy();
  auto rhs_ptr = rhs_op->getType()->isPointerTy();

  // In the original GetPointer code, there is a case that logs an error
  // When both addresses are pointers, because its weird, and I'm not sure
  // why that would be
  if (lhs_ptr && rhs_ptr) {
    llvm::IRBuilder ir(inst->getNextNode());
    const auto bb = ir.GetInsertBlock();

    DLOG(ERROR) << "Two pointers " << remill::LLVMThingToString(lhs_op)
                << " and " << remill::LLVMThingToString(rhs_op)
                << " are added together " << remill::LLVMThingToString(inst)
                << " in block " << bb->getName().str() << " in function "
                << bb->getParent()->getName().str();

    llvm::Value *new_pointer = ir.CreateIntToPtr(inst, inferred_type);
    ReplaceAllUses(inst, new_pointer);
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
        return {inst, false};
      }
      if (!ptr_val->getType()->isPointerTy()) {
        DLOG(ERROR) << "Error! return type is not a pointer: "
                    << remill::LLVMThingToString(ptr_val);

        // Default behavior is just to cast, this is not ideal, because
        // we want to try and propagate as much as we can.
        llvm::IRBuilder ir(inst->getNextNode());
        llvm::Value *default_cast = ir.CreateBitCast(inst, inferred_type);

        // ReplaceAllUses(&inst, default_cast);
        return {default_cast, true};
      }

      CHECK_EQ(ptr_val->getType()->isPointerTy(), 1);

      // ^ should be in updated vals. Next create an indexed pointer
      // This could be a GEP, but in some cases might just be a bitcast.
      auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(rhs_op);
      if (!rhs_const && !rhs_inst) {
        DLOG(ERROR) << "Error! RHS is not const or inst\n";
        return {inst, false};
      }
      llvm::IRBuilder ir(inst);
      llvm::Value *indexed_pointer;
      if (rhs_const) {
        indexed_pointer =
            GetIndexedPointer(ir, ptr_val, rhs_const, inferred_type);
      } else {
        indexed_pointer =
            GetIndexedPointer(ir, ptr_val, rhs_inst, inferred_type);
      }

      // Mark as updated
      return {indexed_pointer, true};

      // Same but for RHS
    } else if (rhs_inst) {
      auto [ptr_val, changed] = visitInferInst(rhs_inst, inferred_type);
      if (!changed) {
        return {inst, false};
      }

      // TODO (Carson) Confirm pointer type.
      auto lhs_const = llvm::dyn_cast<llvm::ConstantInt>(lhs_op);
      if (!lhs_const && !lhs_inst) {
        DLOG(ERROR) << "Error! LHS is not const or inst\n";
        return {inst, false};
      }
      llvm::IRBuilder ir(inst);
      llvm::Value *indexed_pointer;
      if (lhs_const) {
        indexed_pointer =
            GetIndexedPointer(ir, ptr_val, lhs_const, inferred_type);
      } else {
        indexed_pointer =
            GetIndexedPointer(ir, ptr_val, lhs_inst, inferred_type);
      }

      // Mark as updated
      return {indexed_pointer, true};

      // We know there is some pointer info, but they are both consts?
    } else {

      // We don't have a L/RHS instruction, just create a pointer
      llvm::IRBuilder ir(inst->getNextNode());
      llvm::Value *add_ptr = ir.CreateIntToPtr(inst, inferred_type);
      CopyMetadataTo(inst, add_ptr);
      return {add_ptr, true};
    }
  }

  // Default behavior is just to cast, this is not ideal, because
  // we want to try and propagate as much as we can.
  llvm::IRBuilder ir(inst->getNextNode());
  llvm::Value *default_cast = ir.CreateBitCast(inst, inferred_type);

  // ReplaceAllUses(&inst, default_cast);
  return {default_cast, true};
}

std::pair<llvm::Value *, bool>
PointerLifter::visitReturnInst(llvm::ReturnInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }
  if (auto return_op = llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0))) {
    auto [new_ptr, worked] = visitInferInst(return_op, inferred_type);
    if (worked) {

      // Create a new return and replace the current one.
      llvm::IRBuilder<> ir(&inst);
      llvm::Value *new_ret = ir.CreateRet(new_ptr);
      ReplaceAllUses(&inst, new_ret);
      return {new_ret, true};
    }
  }
  return {&inst, false};
}

std::pair<llvm::Value *, bool>
PointerLifter::visitStoreInst(llvm::StoreInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }
  // Stores by themselves are void types
  // If we have an argument like store <large_int>, int*,
  // But we learn that this <large_int>, maybe a const, is an int*
  // Do later
  return {&inst, false};
}

std::pair<llvm::Value *, bool>
PointerLifter::visitAllocaInst(llvm::AllocaInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }
  // If we've inferred a new type for alloca, lets just make a new alloca
  llvm::IRBuilder<> ir(&inst);
  llvm::Value *new_alloca = ir.CreateAlloca(inferred_type);
  return {new_alloca, true};
}

std::pair<llvm::Value *, bool>
PointerLifter::visitSExtInst(llvm::SExtInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }
  if (auto pointer_inst =
          llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0))) {
    auto [new_ptr, worked] = visitInferInst(pointer_inst, inferred_type);
    if (worked) {
      ReplaceAllUses(&inst, new_ptr);
      return {new_ptr, true};
    }
  }
  return {&inst, false};
}

std::pair<llvm::Value *, bool>
PointerLifter::visitZExtInst(llvm::ZExtInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }
  if (auto pointer_inst =
          llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0))) {
    auto [new_ptr, worked] = visitInferInst(pointer_inst, inferred_type);
    if (worked) {
      ReplaceAllUses(&inst, new_ptr);
      return {new_ptr, true};
    }
  }
  return {&inst, false};
}

// Comparisons are not very interesting here
// The return result is a bool which won't be a pointer
// The interesting case will be to visit constant expressions
std::pair<llvm::Value *, bool>
PointerLifter::visitCmpInst(llvm::CmpInst &inst) {
  llvm::Type *inferred_type = inferred_types[&inst];
  if (!inferred_type) {
    return {&inst, false};
  }
  // TODO (Carson) check parameters for constant expression
  return {&inst, false};
}

/*
This is the driver code for the pointer lifter

It creates a worklist out of the instructions in the original function and
visits them. In order to do downstream pointer propagation, additional uses of
updated values are added into the next_worklist. Pointer lifting for a function
is done when we reach a fixed point, when the next_worklist is empty.
*/

void PointerLifter::LiftFunction(llvm::Function &func) {
  std::vector<llvm::Instruction *> worklist;
  std::vector<llvm::GetElementPtrInst *> gep_list;

  // Preprocessing
  // 1. Flatten geps
  for (auto &block : func) {
    for (auto &inst : block) {
      if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst)) {
        gep_list.push_back(gep_inst);
      }
    }
  }

  for (auto &gep_inst : gep_list) {
    llvm::Value *new_gep = flattenGEP(gep_inst);
    if (gep_inst != new_gep) {
      CopyMetadataTo(gep_inst, new_gep);
      gep_inst->replaceAllUsesWith(new_gep);
    }
  }
  // Deadcode remove stale geps.
  llvm::FunctionPassManager fpm(false);
  llvm::FunctionAnalysisManager fam;
  fam.registerPass([&] { return llvm::TargetLibraryAnalysis(); });
  fam.registerPass([&] { return llvm::PassInstrumentationAnalysis(); });
  fpm.addPass(llvm::DCEPass());
  fpm.run(func, fam);

  made_progress = true;
  for (auto i = 0u; i < max_gas && made_progress; ++i) {
    made_progress = false;

    for (auto &block : func) {
      for (auto &inst : block) {
        worklist.push_back(&inst);
      }
    }

    for (auto inst : worklist) {
      visit(inst);
    }
    worklist.clear();

    // Note (For Peter): The reason we are doing deletion here instead of the
    // end, is that if we don't we keep iterating over what should be dead code,
    // and then we would have to keep track of instructions we have seen before,
    // but depending on changes we make, instructions we have seen before might
    // need to be updated anyway... it gets messy. Removing dead code at the end
    // of each iteration guarantees convergence

    // NOTE(Carson): We had a thought about how to change this... but i can't remember
    for (auto inst : to_remove) {
      if (auto rep_inst = rep_map[inst];
          rep_inst && rep_inst->getType() == inst->getType()) {

        // DLOG(ERROR) << "Replacing:\n";
        // DLOG(ERROR) << remill::LLVMThingToString(inst) << "\n";
        // DLOG(ERROR) << remill::LLVMThingToString(rep_inst) << "\n";
        CopyMetadataTo(inst, rep_inst);
        inst->replaceAllUsesWith(rep_inst);
      } else {
        DLOG(ERROR) << "Can't replace these two:\n";
        DLOG(ERROR) << remill::LLVMThingToString(inst) << "\n";
        DLOG(ERROR) << remill::LLVMThingToString(rep_inst) << "\n";
      }
    }
    for (auto inst : to_remove) {
      if (inst->use_empty()) {
        inst->eraseFromParent();
        rep_map.erase(inst);
        inferred_types.erase(inst);
        next_inferred_types.erase(inst);
      }
    }
    rep_map.clear();
    inferred_types.clear();
    next_inferred_types.clear();
    to_remove.clear();

    fpm.run(func, fam);
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
void AddBrightenPointerOperations(llvm::FunctionPassManager &fpm,
                                  unsigned max_gas) {
  fpm.addPass(PointerLifterPass(max_gas));
}
}  // namespace anvill
