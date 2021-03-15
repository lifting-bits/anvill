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

#include <anvill/Transforms.h>
#include "BrightenPointerOperations.h"
#include <glog/logging.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/IR/LegacyPassManager.h>
#include <remill/BC/Util.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <utility>


namespace anvill {
char PointerLifterPass::ID = '\0';

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
  inferred_types[inst] = inferred_type;
  auto [ret_val, succ] = visit(inst);
  inferred_types.erase(inst);
  return {ret_val, succ};
}


llvm::Value *
PointerLifter::GetIndexedPointer(llvm::IRBuilder<> &ir, llvm::Value *address,
                                 llvm::Value *offset, llvm::Type *dest_type) {
  auto &context = mod->getContext();
  const auto &dl = mod->getDataLayout();
  auto i32_ty = llvm::Type::getInt32Ty(context);
  auto i8_ty = llvm::Type::getInt8Ty(context);
  auto i8_ptr_ty = i8_ty->getPointerTo();

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

// MUST have an implementation of this if llvm:InstVisitor retun type is not void.
std::pair<llvm::Value *, bool>
PointerLifter::visitInstruction(llvm::Instruction &I) {
  LOG(ERROR) << "PointerLifter unknown instruction "
             << remill::LLVMThingToString(&I) << "\n";
  return {&I, false};
}
/*
    Replace next_worklist iteration with just a bool `changed`, set changed=true here.
    iterate over the original worklist until changed is false.

    is there a bad recursion case here?

    Create map from Value --> Value, maintains seen/cached changes.
*/

void PointerLifter::ReplaceAllUses(llvm::Value *old_val, llvm::Value *new_val) {
  DCHECK(!llvm::isa<llvm::Constant>(old_val));
  for (auto user : old_val->users()) {
    if (auto inst = llvm::dyn_cast<llvm::Instruction>(user)) {
      next_worklist.push_back(inst);
    }
  }
  llvm::Instruction *old_inst = llvm::dyn_cast<llvm::Instruction>(old_val);
  to_remove.insert(old_inst);
  rep_map[old_inst] = new_val;
  changed = true;
  // old_val->replaceAllUsesWith(new_val);
  // TODO Carson, after visitInferInst, remove stuff from the map upon return!
}

/*
BitCasts can give more information about intended types, lets look at this example

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

Technically, when originally lifting we learned that the parameter is a pointer, BUT
in %2, %3, %4 you can see that its treating the pointer as a raw character pointer, then
in %5 converts it to a i32, which it loads and returns.

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
  if (inferred_types.find(&inst) != inferred_types.end()) {

    // If there is a bitcast that we could not eliminate for some reason (fell through the default case with ERROR)
    // There might be a bitcast downstream which knows more than us, and wants us to update our bitcast.
    // So we just create a new bitcast, replace the current one, and return
    llvm::IRBuilder ir(&inst);
    llvm::Type *inferred_type = inferred_types[&inst];
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
  // TODO (Carson) make sure in the visitor methods that we dont assume inferred type is the return type, we can fail!
  LOG(ERROR) << "BitCast, unknown operand type: "
             << remill::LLVMThingToString(inst.getOperand(0)->getType());
  return {&inst, false};
}

// This function checks for two cases. 
// 1. This checks to see if the last index is a const or variable, if it isnt a const we dont rewrite.
// 2. Depending on the offset and inferred type, if the newly calculated offset is not divisible by the type size
// we don't rewrite.
// This code is taken from Peter's PeelLastIndex :)  
bool
PointerLifter::canRewriteGep(llvm::GetElementPtrInst& gep, llvm::Type* inferred_type) {

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
  auto dl = mod->getDataLayout();
  // Figure out what the last index was represented in terms of a byte offset.
  // We need to be careful about negative indices -- we want to maintain them,
  // but we don't want division/remainder to produce different roundings.
  const auto gep_elem_type_size =
      dl.getTypeAllocSize(gep.getResultElementType()).getFixedSize();
  const auto last_index_i = last_index->getSExtValue() *
                            static_cast<int64_t>(gep_elem_type_size);
  const long long last_index_ai = std::abs(last_index_i);
  const auto last_index_sign = (last_index_i / std::max(last_index_ai, 1ll));
  auto elem_size = static_cast<int64_t>(
      dl.getTypeAllocSize(gep.getResultElementType()).getFixedSize());
  // The last index does not evenly divide the size of the result
  // element type. Case 2
  if ((last_index_ai % elem_size)) {
    return false;
  }
  return true;
}
// This function turns GEPS with multiple indicies into multiple geps each with 1 index. 
// Why? Sometimes GEP indexes are not constant, so you cant just divide by them all. 
std::pair<llvm::Value*, bool> PointerLifter::flattenGEP(llvm::GetElementPtrInst *gep) {


}
// TODO (Carson) maybe change back to pointer type.
// TODO (Carson) gep is not a good name for this shenanigans
std::pair<llvm::Value*, bool> 
PointerLifter::BrightenGEP_PeelLastIndex(llvm::GetElementPtrInst *gep, llvm::Type *inferred_type) {
  // TODO (Carson) refactor this to use canRewriteGEP
  LOG(ERROR) << "================================================\n";
  LOG(ERROR) << remill::LLVMThingToString(gep) << " < gep is\n";
  LOG(ERROR) << remill::LLVMThingToString(gep->getType()) << "< gep type\n";
  LOG(ERROR) << gep->getType()->isStructTy() << " < is struct ty? \n";
  LOG(ERROR) << gep->getType()->isVectorTy() << " < is vector ty? \n";
  LOG(ERROR) << gep->getType()->isPointerTy() << " < is pointer ty?\n";
  LOG(ERROR) << remill::LLVMThingToString(inferred_type) << " < gep inferred type is\n";

  if (gep->getType()->isPointerTy()) {
    LOG(ERROR) << remill::LLVMThingToString(gep->getType()->getPointerElementType()) << " < pointer ele type\n";
    LOG(ERROR) << gep->getType()->getPointerElementType()->isStructTy() << " < ele is struct?\n";
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
  auto gep_element_type = llvm::PointerType::get(gep->getResultElementType(),
                                         gep->getPointerAddressSpace());
  auto inferred_element_type = llvm::PointerType::get(inferred_type->getPointerElementType(),
                                         inferred_type->getPointerAddressSpace());
  llvm::SmallVector<llvm::Value *, 4> indices;
  for (auto it = gep->idx_begin(); it != gep->idx_end(); ++it) {
    indices.push_back(it->get());
  }
  // If the last index isn't a constant then we can't peel it off.
  auto last_index = llvm::dyn_cast<llvm::ConstantInt>(indices.pop_back_val());
  if (!last_index) {
    return {gep, false};
  }
  auto dl = mod->getDataLayout();

  // Figure out what the last index was represented in terms of a byte offset.
  // We need to be careful about negative indices -- we want to maintain them,
  // but we don't want division/remainder to produce different roundings.
  const auto gep_elem_type_size = dl.getTypeAllocSize(gep->getType()->getPointerElementType()).getFixedSize();
  const auto inferred_ele_type_size = dl.getTypeAllocSize(inferred_type->getPointerElementType()).getFixedSize();
  const auto last_index_i = last_index->getSExtValue();
  const auto index_value = std::abs(last_index_i) * static_cast<uint64_t>(gep_elem_type_size);
  const auto last_index_sign = (last_index_i) ? 1 : -1;
  
  // Error case, in the case our inferred type size is greater than the offset
  // Lets not break anything. dont do it. 
  // imagine you have an i8* with offset 1 byte, and a cast to i32*, you can't represent that 1 byte with a complete index 
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
  LOG(ERROR) << "inferred elem type size (bytes): " << inferred_ele_type_size << "\n";
  LOG(ERROR) << "last_index of this GEP (as gep type): " << last_index_i << "\n";
  LOG(ERROR) << "last_index actual value(bits) : " << index_value << "\n";
  LOG(ERROR) << "last_index of this GEP (as inferred_type): " << size_adjusted_index << "\n";
  LOG(ERROR) << "last_index element sign : " << last_index_sign << "\n";
  // LOG(ERROR) << "Size adjusted index (for whatever the new type is): " << size_adjusted_index << "=" <<  / "gep_elem_type_size\n";
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
    LOG(ERROR) << " Source element type: " << remill::LLVMThingToString(src_element_type) << "\n";
    LOG(ERROR) << " Source type: " << remill::LLVMThingToString(src->getType()) << "\n";
    LOG(ERROR) << " Source: " << remill::LLVMThingToString(src) << "\n";
    new_src = ir.CreateGEP(src->getType()->getPointerElementType(), src, indices);
  }
  llvm::Instruction* new_src_inst = llvm::dyn_cast<llvm::Instruction>(new_src);
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
      last_index->getType(),
      last_index_sign * size_adjusted_index, true));
  llvm::IRBuilder<> ir(gep);
  // Casted source should be inferred_type, so get the element type
  const auto new_gep = ir.CreateGEP(inferred_type->getPointerElementType(), casted_src, indices);
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
  if (inferred_types.find(&inst) == inferred_types.end()) {
    return {&inst, false};
  }

  llvm::Type *inferred_type = inferred_types[&inst];
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

In the first case, only %X is a pointer, this should already be known by the compiler
In the second case, it indicates that %Y although of type integer, has been a pointer

*/
std::pair<llvm::Value *, bool>
PointerLifter::visitIntToPtrInst(llvm::IntToPtrInst &inst) {

  llvm::Value *pointer_operand = inst.getOperand(0);
  LOG(ERROR) << "in intoptr, this should be a pointer! "
             << remill::LLVMThingToString(pointer_operand) << "\n";
  if (auto pointer_inst = llvm::dyn_cast<llvm::Instruction>(pointer_operand)) {
    LOG(ERROR) << "Visiting a pointer instruction: "
               << remill::LLVMThingToString(&inst) << "\n";

    // This is the inferred type
    llvm::Type *dest_type = inst.getDestTy();

    // Propagate that type upto the original register containing the value
    // Create an entry in updated val with pointer cast.
    auto [new_ptr, changed] = visitInferInst(pointer_inst, dest_type);

    // If we succeded, it should be a pointer type!
    if (changed && new_ptr->getType()->isPointerTy()) {
      ReplaceAllUses(&inst, new_ptr);
      return {new_ptr, true};
    }
    LOG(ERROR)
        << "Failed to promote IntToPtr inst, return type is not a pointer: "
        << remill::LLVMThingToString(new_ptr) << "\n";
    return {&inst, false};
  }

  // TODO(pag): Disabled this; the addition of an extra named constant might
  //            has a different address than the original, so this would serve
  //            only to introduce an additional load if the original behavior
  //            is maintained.
   // Its a constant expression where we are doing inttoptr of a constant int.
   // We can create a new constant expression
  //  if (auto pointer_const = llvm::dyn_cast<llvm::ConstantInt>(pointer_operand)) {
  //    llvm::Type *inferred_type = inferred_types[&inst];
  //    llvm::Value *new_global = new llvm::GlobalVariable(
  //        mod, inferred_type, true, llvm::GlobalValue::PrivateLinkage,
  //        pointer_const);
  //    // TODO (Carson), point this out to Peter, he will tell you its bad :)
  //    // ReplaceAllUses(&inst, new_global);
  //    //to_remove.insert(&inst);
  //    return {new_global, true};
  //  }
  return {&inst, false};
}

/*
  %4 = load i64, i64* inttoptr (i64 6295600 to i64*), align 16
  %5 = add i64 %4, 128
  %6 = inttoptr i64 %5 to i32*

  In order to collapse the inttoptr, add into a GEP, the load also needs to have its type promoted to a pointer
  
  %4 = load i32*, i32** %some_global/constant_expr, align 16
  %5 = GEP i32, %4, 32
*/
std::pair<llvm::Value *, bool>
PointerLifter::visitLoadInst(llvm::LoadInst &inst) {
  if (inferred_types.find(&inst) == inferred_types.end()) {
    LOG(ERROR) << "No type info for load! Returning just the load\n";
    return {&inst, false};
  }
  llvm::Type *inferred_type = inferred_types[&inst];

  // Assert that the CURRENT type of the load (in the example i64) and the new promoted type (i32*)
  // Are of the same size in bytes.
  // This prevents us from accidentally truncating/extending when we don't want to
  auto dl = mod->getDataLayout();
  CHECK_EQ(dl.getTypeAllocSizeInBits(inst.getType()),
           dl.getTypeAllocSizeInBits(inferred_type));

  // Load operand can be another instruction
  if (llvm::Instruction *possible_mem_loc = llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0))) {
    LOG(ERROR) << "Load operand is an instruction! " << remill::LLVMThingToString(possible_mem_loc) << "\n";


    // Load from potentially a new addr.
    auto [maybe_new_addr, changed] = visitInferInst(possible_mem_loc, inferred_type->getPointerTo());
    if (!changed) {
      LOG(ERROR) << "Failed to promote load! Operand type not promoted "
                 << remill::LLVMThingToString(maybe_new_addr) << "\n";
      return {&inst, false};
    }
    // Create a new load instruction with type inferred_type which loads a ptr to inferred_type
    llvm::IRBuilder ir(&inst);
    LOG(ERROR) << remill::LLVMThingToString(&inst) << "< current load\n";
    LOG(ERROR) << remill::LLVMThingToString(inferred_type) << " < inferred type to load\n";
    LOG(ERROR) << remill::LLVMThingToString(maybe_new_addr) << " < new inst\n";
    LOG(ERROR) << remill::LLVMThingToString(maybe_new_addr->getType()) << " < new inst type, should be * to the first\n";
    llvm::Value *promoted_load = ir.CreateLoad(inferred_type, maybe_new_addr);
    LOG(ERROR) << "new load: " << remill::LLVMThingToString(promoted_load) << "\n";
    // If we have done some optimization and have a new var to load from, replace operand with new value.
    // if (maybe_new_addr != possible_mem_loc) {
    //    inst.setOperand(0, maybe_new_addr);
    // }
    ReplaceAllUses(&inst, promoted_load);
    return {promoted_load, true};
  }
  // Load operand can be a constant expression
  if (llvm::ConstantExpr *const_expr =
          llvm::dyn_cast<llvm::ConstantExpr>(inst.getOperand(0))) {
    LOG(ERROR) << "Load operand is a constant expression! "
               << remill::LLVMThingToString(const_expr) << "\n";

    // TODO (Carson) create constant expression handler?
    // If we have a constant expression, thats okay. This is going to be our original
    // ReplaceAllUses(&inst, const_expr);
    // return const_expr;
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
      ReplaceAllUses(&inst, promoted_load);
      // Remove expr_as_inst
      ReplaceAllUses(expr_as_inst, const_expr);
      return {promoted_load, true};
    }
    // expr_as_inst->eraseFromParent();
    llvm::IRBuilder ir(&inst);
    llvm::Value *promoted_load = ir.CreateLoad(inferred_type, new_const_ptr);
    ReplaceAllUses(&inst, promoted_load);
    ReplaceAllUses(expr_as_inst, const_expr);

    return {promoted_load, true};
  }
  return {&inst, false};
}

/*
Binary operators such as add, sub, mul, etc

Ultimately we want to eliminate the operation and replace it with a GEP when we can,
or just cast the result if is needed.

Here is an example with an add.

Original:
%A = i32 419444 <------- Here we see that %A is an i32, create a new pointer for this.
%B = i32 add %A 8 <---------- Here we see that %B is an add, Visit the instruction %A
%C = inttoptr %B <---- Here we infer that %B is really a pointer. Visit %B
-----------------------^ Start

Intermediate
%A = i32 419444
%A_PTR = i32* 41944 <------- Create a new ptr type, Mark updated vals as A ---> A_PTR
%B = i32 add %A 8
%C = inttoptr %B

Intermediate 2
%A = i32 419444
%A_PTR = i32* 41944
%B = i32 add %A 8
%B_GEP = i32* GEP %A_PTR, <indexes> <--- Visit returns with the new A_PTR, Create a GEP, B ---> B_GEP
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
  if (inferred_types.find(&inst) == inferred_types.end()) {
    return {&inst, false};
  }
  llvm::Type *inferred_type = inferred_types[&inst];

  // If we are coming from downstream, then we have an inferred type.
  const auto lhs_op = inst.getOperand(0);
  const auto rhs_op = inst.getOperand(1);

  auto lhs_ptr = lhs_op->getType()->isPointerTy();
  auto rhs_ptr = rhs_op->getType()->isPointerTy();

  // In the original GetPointer code, there is a case that logs an error
  // When both addresses are pointers, because its weird, and im not sure why that would be
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
  }

  // If neither of them are known pointers, then we have some inference to propagate!
  else if (!lhs_ptr && !rhs_ptr) {
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

      // TODO (Carson) Sanity check this, but the return value from visitInferInst
      // Could be a constant pointer, or an instruction. Where should the insert point be?
      // Create the GEP/Indexed pointer
      llvm::IRBuilder ir(lhs_inst);
      llvm::Value *indexed_pointer =
          GetIndexedPointer(ir, ptr_val, rhs_const, inferred_type);

      // Mark as updated
      ReplaceAllUses(&inst, indexed_pointer);
      return {indexed_pointer, true};
    }
    // Same but for RHS
    else if (rhs_inst) {
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
    }
    // We know there is some pointer info, but they are both consts?
    else {

      // We don't have a L/RHS instruction, just create a pointer
      llvm::IRBuilder ir(inst.getNextNode());
      llvm::Value *add_ptr = ir.CreateIntToPtr(&inst, inferred_type);

      // ReplaceAllUses(&inst, add_ptr);
      return {add_ptr, true};
    }
  }

  // Default behavior is just to cast, this is not ideal, because
  // we want to try and propagate as much as we can.
  llvm::IRBuilder ir(inst.getNextNode());
  llvm::Value *default_cast = ir.CreateBitCast(&inst, inferred_type);

  // ReplaceAllUses(&inst, default_cast);
  return {default_cast, true};
}
/*
This is the driver code for the pointer lifter

It creates a worklist out of the instructions in the original function and visits them.
In order to do downstream pointer propagation, additional uses of updated values are added into the next_worklist
Pointer lifting for a function is done when we reach a fixed point, when the next_worklist is empty.
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
void PointerLifter::LiftFunction(llvm::Function& func) {
  std::vector<llvm::Instruction *> worklist;

do {
  changed = false;
  func.print(llvm::errs(), nullptr);
  for (auto &block : func) {
    for (auto &inst : block) {
      worklist.push_back(&inst);
    }
  }
    for (auto inst : worklist) {
      visit(inst);
    }

    // Note (For Peter): The reason we are doing deletion here instead of the end, 
    // is that if we don't we keep iterating over what should be dead code, and then we would have to keep track of instructions we have seen before,
    // but depending on changes we make, instructions we have seen before might need to be updated anyway... it gets messy. Removing dead code at the end
    // of each iteration guarantees convergence
    for (auto &inst : to_remove) {
      if (inst->getNumUses() > 0) {
      //if (inst->use_empty()) {
        auto rep_inst = rep_map[inst];
        if (rep_inst->getType() == inst->getType()) {
          inst->replaceAllUsesWith(rep_inst);
          inst->eraseFromParent();
        }
      }
    }
  llvm::legacy::FunctionPassManager fpm(mod);
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createDeadInstEliminationPass());
  fpm.doInitialization();
  fpm.run(func);
  fpm.doFinalization();

    worklist.clear();
  } while (changed);
}

bool PointerLifterPass::runOnFunction(llvm::Function &f) {
  auto mod = f.getParent();
  PointerLifter lifter(mod, xref_resolver);
  lifter.LiftFunction(f);
  // TODO (Carson) have an analysis function which determines modifications
  // Then use lift function to run those modifications 
  // Can return true/false depending on what was modified
  return true;
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
llvm::FunctionPass *
CreateBrightenPointerOperations(const CrossReferenceResolver &resolver) {
  return new PointerLifterPass(resolver);
}

}  // namespace anvill
