#include "anvill/PointerLifter.h"

#include <glog/logging.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <utility>

namespace anvill {


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
  return visit(inst);
}


llvm::Value *
PointerLifter::GetIndexedPointer(llvm::IRBuilder<> &ir, llvm::Value *address,
                                 llvm::Value *offset, llvm::Type *dest_type) {
  auto &context = module.getContext();
  const auto &dl = module.getDataLayout();
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
  to_replace.emplace_back(old_inst, new_val);

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
    llvm::Type *possible_pointer_ty = pointer_inst->getType();
    if (!possible_pointer_ty->isPointerTy()) {
      return {&inst, false};
    }
    // If we are bitcasting to a pointer, propagate that info!
    auto [new_var_type, opt_success] =
        visitInferInst(pointer_inst, possible_pointer_ty);
    if (opt_success) {
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

// TODO (Carson) monday or later
std::pair<llvm::Value *, bool>
PointerLifter::visitGetElementPtrInst(llvm::GetElementPtrInst &inst) {
  if (inferred_types.find(&inst) != inferred_types.end()) {

    // If there is an inferred type for this inst, our GEP type might be inaccurate
    // https://releases.llvm.org/3.3/docs/LangRef.html#getelementptr-instruction
    llvm::Type *inferred_type = inferred_types[&inst];
    llvm::Instruction *pointer_inst =
        llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0));
    CHECK_NE(pointer_inst, nullptr);
    auto [new_pointer, changed] = visitInferInst(pointer_inst, inferred_type);
    if (new_pointer->getType() != inferred_type) {
    }
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
  //  // Its a constant expression where we are doing inttoptr of a constant int.
  //  // We can create a new constant expression
  //  if (auto pointer_const = llvm::dyn_cast<llvm::ConstantInt>(pointer_operand)) {
  //    llvm::Type *inferred_type = inferred_types[&inst];
  //    llvm::Value *new_global = new llvm::GlobalVariable(
  //        module, inferred_type, true, llvm::GlobalValue::PrivateLinkage,
  //        pointer_const);
  //    // TODO (Carson), point this out to Peter, he will tell you its bad :)
  //    // ReplaceAllUses(&inst, new_global);
  //    //to_remove.insert(&inst);
  //    return new_global;
  //  }
  return {&inst, false};
}

// // TODO (Carson) change func name, its not a true visitor.
// // This function recursively iterates through a constant expression until it hits a constant int,
// llvm::ConstantExpr *
// PointerLifter::visitConstantExpr(llvm::ConstantExpr &constant_expr) {}

// If you are visiting a load like this
/*
  %4 = load i64, i64* inttoptr (i64 6295600 to i64*), align 16
  %5 = add i64 %4, 128
  %6 = inttoptr i64 %5 to i32*
*/

// In order to collapse the inttoptr, add into a GEP, the load also needs to have its type promoted to a pointer
/*
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

  // Here we know that the result of a load is a pointer
  // So we must promote the load value to be that of a pointer value
  llvm::Type *ptr_to_ptr = inferred_type;

  // Assert that the CURRENT type of the load (in the example i64) and the new promoted type (i32*)
  // Are of the same size in bytes.
  // This prevents us from accidentally truncating/extending when we don't want to
  auto dl = module.getDataLayout();
  CHECK_EQ(dl.getTypeAllocSizeInBits(inst.getType()),
           dl.getTypeAllocSizeInBits(inferred_type));

  // Load operand can be another instruction
  if (llvm::Instruction *possible_mem_loc =
          llvm::dyn_cast<llvm::Instruction>(inst.getOperand(0))) {
    LOG(ERROR) << "Load operand is an instruction! "
               << remill::LLVMThingToString(possible_mem_loc) << "\n";


    // Load from potentially a new addr.
    auto [maybe_new_addr, changed] =
        visitInferInst(possible_mem_loc, ptr_to_ptr);
    if (maybe_new_addr->getType() != ptr_to_ptr) {
      LOG(ERROR) << "Failed to promote load! Operand type not promoted "
                 << remill::LLVMThingToString(maybe_new_addr) << "\n";
      return {&inst, false};
    }
    // Create a new load instruction with type inferred_type which loads a ptr to inferred_type
    llvm::IRBuilder ir(&inst);
    llvm::Value *promoted_load = ir.CreateLoad(inferred_type, maybe_new_addr);

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

    // Rather than passing in the inferred resulting type to this load, pass in the type that matches the load.

    auto [new_const_ptr, changed] = visitInferInst(expr_as_inst, ptr_to_ptr);

    llvm::IRBuilder ir(&inst);
    llvm::Value *promoted_load = ir.CreateLoad(inferred_type, new_const_ptr);

    ReplaceAllUses(&inst, promoted_load);

    // to_remove.insert(&inst);
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
void PointerLifter::LiftFunction(llvm::Function *func) {
  std::vector<llvm::Instruction *> worklist;
  std::vector<llvm::Instruction *> next_worklist;

  for (auto &block : *func) {
    for (auto &inst : block) {
      worklist.push_back(&inst);
    }
  }
  do {
    for (auto inst : worklist) {
      visit(inst);
    }

    for (auto &pair : to_replace) {
      pair.first->replaceAllUsesWith(pair.second);
    }
    to_replace.clear();

    for (auto &inst : to_remove) {
      CHECK_EQ(inst->getNumUses(), 0);
      inst->eraseFromParent();
    }
    to_remove.clear();

    worklist.swap(next_worklist);
    next_worklist.clear();

    // Remove duplicate instructions.
    std::sort(worklist.begin(), worklist.end());
    auto it = std::unique(worklist.begin(), worklist.end());
    worklist.erase(it, worklist.end());

  } while (!next_worklist.empty());
}

};  // namespace anvill
