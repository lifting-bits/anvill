/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include "anvill/Optimize.h"

#include <glog/logging.h>

// clang-format off
#include <remill/BC/Compat/CTypes.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Utils/Local.h>

// clang-format on

#include <remill/BC/ABI.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>

#include <unordered_set>
#include <vector>

#include "anvill/Analyze.h"
#include "anvill/Decl.h"
#include "anvill/Program.h"
#include "anvill/RecoverMemRefs.h"
#include "anvill/Util.h"

#include <anvill/Transforms.h>

namespace anvill {
namespace {

// Replace all uses of a specific intrinsic with an undefined value. We actually
// don't use LLVM's `undef` values because those can behave unpredictably
// across different LLVM versions with different optimization levels. Instead,
// we use a null value (zero, really).
static void ReplaceUndefIntrinsic(llvm::Function *function) {
  auto call_insts = remill::CallersOf(function);
  auto undef_val = llvm::Constant::getNullValue(function->getReturnType());
  for (auto call_inst : call_insts) {
    call_inst->replaceAllUsesWith(undef_val);
    call_inst->removeFromParent();
    delete call_inst;
  }
}

static void RemoveFunction(llvm::Function *func) {
  if (!func->hasNUsesOrMore(1)) {
    func->eraseFromParent();
  } else {
    auto ret_type = func->getReturnType();
    if (!ret_type->isVoidTy()) {
      func->replaceAllUsesWith(llvm::UndefValue::get(func->getType()));
      func->eraseFromParent();
    }
  }
}


// Remove calls to the various undefined value intrinsics.
static void RemoveUndefFuncCalls(llvm::Module &module) {
  llvm::Function *undef_funcs[] = {
      module.getFunction("__remill_undefined_8"),
      module.getFunction("__remill_undefined_16"),
      module.getFunction("__remill_undefined_32"),
      module.getFunction("__remill_undefined_64"),
      module.getFunction("__remill_undefined_f32"),
      module.getFunction("__remill_undefined_f64"),
  };

  for (auto undef_func : undef_funcs) {
    if (undef_func) {
      ReplaceUndefIntrinsic(undef_func);
      RemoveFunction(undef_func);
    }
  }
}

// Used to remove the calls to functions that don't really have a big
// side-effect, but which Clang can't just remove because it can't be
// sure, e.g. `fpclassify`.
static void
RemoveUnusedCalls(llvm::Module &module, const char *func_name,
                  std::unordered_set<llvm::Function *> &changed_funcs) {
  auto func = module.getFunction(func_name);
  if (!func) {
    return;
  }

  std::vector<llvm::CallInst *> to_remove;

  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      if (llvm::isInstructionTriviallyDead(call_inst)) {
        to_remove.push_back(call_inst);
      }
    }
  }

  for (auto call_inst : to_remove) {
    auto in_block = call_inst->getParent();
    auto in_func = in_block->getParent();
    changed_funcs.insert(in_func);

    call_inst->eraseFromParent();
  }
}

// Look for compiler barriers (empty inline asm statements marked
// with side-effects) and try to remove them. If we see some barriers
// bracketed by extern
static void RemoveUnneededInlineAsm(const Program &program,
                                    llvm::Module &module) {
  std::vector<llvm::CallInst *> to_remove;

  program.ForEachFunction([&](const FunctionDecl *decl) -> bool {
    const auto func =
        decl->DeclareInModule(CreateFunctionName(decl->address), module);
    if (func->isDeclaration()) {
      return true;
    }

    to_remove.clear();

    for (llvm::BasicBlock &block : *func) {
      auto prev_is_compiler_barrier = false;
      llvm::CallInst *prev_barrier = nullptr;
      for (auto &inst : block) {
        if (llvm::CallInst *call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
          const auto inline_asm =
              llvm::dyn_cast<llvm::InlineAsm>(call_inst->getCalledOperand());
          if (inline_asm) {

            // It looks like a "fake" read from a register.
            if (!call_inst->hasNUsesOrMore(1) &&
                !inline_asm->getAsmString().find("# read register ")) {
              to_remove.push_back(call_inst);
              prev_is_compiler_barrier = false;
              prev_barrier = nullptr;

            } else if (inline_asm->hasSideEffects() &&
                       call_inst->getType()->isVoidTy() &&
                       inline_asm->getAsmString().empty()) {

              if (prev_is_compiler_barrier) {
                to_remove.push_back(call_inst);
              } else {
                prev_barrier = call_inst;
              }
              prev_is_compiler_barrier = true;

            } else {
              prev_is_compiler_barrier = false;
              prev_barrier = nullptr;
            }

          } else if (auto target_func = call_inst->getCalledFunction()) {
            if (target_func->hasExternalLinkage()) {
              if (prev_is_compiler_barrier && prev_barrier) {
                to_remove.push_back(prev_barrier);
              }
              prev_is_compiler_barrier = true;
            } else {
              prev_is_compiler_barrier = false;
            }

            prev_barrier = nullptr;

          } else {
            prev_is_compiler_barrier = false;
            prev_barrier = nullptr;
          }
        } else {
          prev_is_compiler_barrier = false;
          prev_barrier = nullptr;
        }
      }
    }

    for (auto call_inst : to_remove) {
      call_inst->eraseFromParent();
    }

    return true;
  });
}

// Get the address space of a pointer value/type, using `addr_space` as our
// backup if it doesn't seem like a pointer with a nown address space.
static unsigned GetPointerAddressSpace(llvm::Value *val, unsigned addr_space) {
  if (addr_space || !val) {
    return addr_space;
  }

  if (auto source_type = llvm::dyn_cast<llvm::PointerType>(val->getType())) {
    addr_space = source_type->getPointerAddressSpace();
    if (addr_space) {
      return addr_space;
    }
  }

  if (auto as_bc = llvm::dyn_cast<llvm::BitCastOperator>(val)) {
    return GetPointerAddressSpace(as_bc->getOperand(0), addr_space);

  } else if (auto as_pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return GetPointerAddressSpace(as_pti->getOperand(0), addr_space);

  } else if (auto as_itp = llvm::dyn_cast<llvm::IntToPtrInst>(val)) {
    return GetPointerAddressSpace(as_itp->getOperand(0), addr_space);

  } else if (auto as_addr = llvm::dyn_cast<llvm::AddrSpaceCastInst>(val)) {
    return GetPointerAddressSpace(as_addr->getOperand(0), addr_space);

  } else {
    return addr_space;
  }
}

static llvm::Value *FindPointer(llvm::IRBuilder<> &ir, llvm::Value *addr,
                                llvm::Type *elem_type, unsigned addr_space) {

  if (auto as_ptr_to_int = llvm::dyn_cast<llvm::PtrToIntOperator>(addr)) {
    if (!addr_space) {
      addr_space = as_ptr_to_int->getPointerAddressSpace();
    }
    auto curr = as_ptr_to_int->getPointerOperand();
    auto possible = FindPointer(ir, curr, elem_type, addr_space);
    return possible ? possible : curr;

  } else {
    return nullptr;
  }
}

static llvm::Value *GetPointer(const Program &program, llvm::Module &module,
                               llvm::IRBuilder<> &ir, llvm::Value *addr,
                               llvm::Type *elem_type, unsigned addr_space);

static llvm::Value *
GetIndexedPointer(const Program &program, llvm::Module &module,
                  llvm::IRBuilder<> &ir, llvm::Value *lhs, llvm::Value *rhs,
                  llvm::Type *dest_type, unsigned addr_space) {

  auto &context = module.getContext();
  const auto &dl = module.getDataLayout();
  auto i32_ty = llvm::Type::getInt32Ty(context);
  auto i8_ty = llvm::Type::getInt8Ty(context);
  auto i8_ptr_ty = llvm::PointerType::get(i8_ty, addr_space);

  if (auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(rhs)) {
    const auto rhs_index = static_cast<int32_t>(rhs_const->getSExtValue());

    const auto [new_lhs, index] =
        remill::StripAndAccumulateConstantOffsets(dl, lhs);

    llvm::GlobalVariable *lhs_global =
        llvm::dyn_cast<llvm::GlobalVariable>(new_lhs);

    if (lhs_global) {
      if (!index) {
        return ir.CreateBitCast(lhs_global, dest_type);
      }

      // It's a global variable not associated with a native segment, try to
      // index into it in a natural-ish way. We only apply this when the index
      // is positive.
      if (0 < index) {
        auto offset = static_cast<uint64_t>(index);
        return remill::BuildPointerToOffset(ir, lhs_global, offset, dest_type);
      }
    }

    auto lhs_elem_type = lhs->getType()->getPointerElementType();
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
          ptr = ir.CreateGEP(lhs_elem_type, lhs, indices);
        }
      } else {
        const auto pos_rhs_index = static_cast<unsigned>(rhs_index);
        if (!(pos_rhs_index % lhs_el_size)) {
          const auto scaled_index = static_cast<uint64_t>(
              rhs_index / static_cast<int64_t>(lhs_el_size));
          llvm::Value *indices[1] = {
              llvm::ConstantInt::get(i32_ty, scaled_index, false)};
          ptr = ir.CreateGEP(lhs_elem_type, lhs, indices);
        }
      }
    }

    // We got a GEP for the dest, now make sure it's the right type.
    if (ptr) {
      if (lhs->getType() == dest_type) {
        return ptr;
      } else {
        return ir.CreateBitCast(ptr, dest_type);
      }
    }
  }

  auto base = ir.CreateBitCast(lhs, i8_ptr_ty);
  llvm::Value *indices[1] = {ir.CreateTrunc(rhs, i32_ty)};
  auto gep = ir.CreateGEP(i8_ty, base, indices);
  return ir.CreateBitCast(gep, dest_type);
}

// Try to get a pointer for the address operand of a remill memory access
// intrinsic.
static llvm::Value *GetPointerFromInt(llvm::IRBuilder<> &ir, llvm::Value *addr,
                                      llvm::Type *elem_type,
                                      unsigned addr_space) {

  auto dest_type = llvm::PointerType::get(elem_type, addr_space);

  if (auto phi = llvm::dyn_cast<llvm::PHINode>(addr)) {
    const auto old_ipoint = &*(ir.GetInsertPoint());
    ir.SetInsertPoint(phi);

    const auto max = phi->getNumIncomingValues();
    const auto new_phi = ir.CreatePHI(dest_type, max);

    for (auto i = 0u; i < max; ++i) {
      auto val = phi->getIncomingValue(i);
      auto block = phi->getIncomingBlock(i);
      llvm::IRBuilder<> sub_ir(block->getTerminator());
      auto ptr = FindPointer(sub_ir, val, elem_type, addr_space);
      if (ptr) {
        if (ptr->getType() != dest_type) {
          ptr = sub_ir.CreateBitCast(ptr, dest_type);
        }
      } else {
        ptr = sub_ir.CreateIntToPtr(val, dest_type);
      }
      new_phi->addIncoming(ptr, block);
    }

    ir.SetInsertPoint(old_ipoint);

    return new_phi;

  } else {
    return ir.CreateIntToPtr(addr, dest_type);
  }
}

// Try to get a pointer for the address operand of a remill memory access
// intrinsic.
llvm::Value *GetPointer(const Program &program, llvm::Module &module,
                        llvm::IRBuilder<> &ir, llvm::Value *addr,
                        llvm::Type *elem_type, unsigned addr_space) {

  addr_space = GetPointerAddressSpace(addr, addr_space);
  const auto addr_type = addr->getType();
  auto dest_type = llvm::PointerType::get(elem_type, addr_space);

  // Handle this case first so that we don't return early on the `ptrtoint` that
  // may directly reach into the address parameter of the memory access
  // intrinsics.
  if (auto as_itp = llvm::dyn_cast<llvm::IntToPtrInst>(addr); as_itp) {
    llvm::IRBuilder<> sub_ir(as_itp);
    return GetPointer(program, module, sub_ir, as_itp->getOperand(0), elem_type,
                      addr_space);

  // It's a `ptrtoint`, but of the wrong type; lets go back and try to use
  // that pointer.
  } else if (auto as_pti = llvm::dyn_cast<llvm::PtrToIntOperator>(addr);
             as_pti) {
    return GetPointer(program, module, ir, as_pti->getPointerOperand(),
                      elem_type, addr_space);

  // We've found a pointer of the desired type; return :-D
  } else if (addr_type == dest_type) {
    return addr;

  // A missed cross-reference!
  } else if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(addr); ci) {
    const auto ea = ci->getZExtValue();
    if (auto addr = GetAddress(program, module, ea, ir, dest_type); addr) {
      return GetPointer(program, module, ir, addr, elem_type, addr_space);

    } else {
      LOG(WARNING) << "Missed cross-reference target " << std::hex << ea
                   << " to pointer";
      return llvm::ConstantExpr::getIntToPtr(ci, dest_type);
    }

  // It's a constant expression, the one we're interested in is `inttoptr`
  // as we've already handled `ptrtoint` above.
  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(addr); ce) {
    if (ce->getOpcode() == llvm::Instruction::IntToPtr) {
      return GetPointer(program, module, ir, ce->getOperand(0), elem_type,
                        addr_space);

    } else if (addr_type->isIntegerTy()) {
      return llvm::ConstantExpr::getIntToPtr(ce, dest_type);

    } else {
      CHECK(addr_type->isPointerTy());
      return llvm::ConstantExpr::getBitCast(ce, dest_type);
    }

  } else if (llvm::isa<llvm::GlobalValue>(addr)) {
    return ir.CreateBitCast(addr, dest_type);

  } else if (auto as_add = llvm::dyn_cast<llvm::AddOperator>(addr); as_add) {
    const auto lhs_op = as_add->getOperand(0);
    const auto rhs_op = as_add->getOperand(1);
    auto lhs = FindPointer(ir, lhs_op, elem_type, addr_space);
    auto rhs = FindPointer(ir, rhs_op, elem_type, addr_space);

    if (!lhs && !rhs) {

      auto lhs_inst = llvm::dyn_cast<llvm::Instruction>(lhs_op);
      auto lhs_const = llvm::dyn_cast<llvm::ConstantInt>(lhs_op);

      auto rhs_inst = llvm::dyn_cast<llvm::Instruction>(rhs_op);
      auto rhs_const = llvm::dyn_cast<llvm::ConstantInt>(rhs_op);

      // If we see something like the following:
      //
      //    %res = add %lhs_inst, <constant>
      //    %ptr = inttoptr %res
      //
      // Then go find/create a pointer for `%lhs_inst`, then generate a GEP
      // based off of that. This is to address a common pattern that we observe
      // with things like accesses through the stack pointer.
      if (lhs_inst && rhs_const && lhs_inst->hasNUsesOrMore(2)) {
        auto ipoint = lhs_inst->getNextNode();
        while (llvm::isa<llvm::PHINode>(ipoint)) {
          ipoint = ipoint->getNextNode();
        }
        llvm::IRBuilder<> sub_ir(ipoint);
        lhs = GetPointer(program, module, sub_ir, lhs_inst, elem_type,
                         addr_space);

      } else if (lhs_const && rhs_inst && rhs_inst->hasNUsesOrMore(2)) {
        auto ipoint = rhs_inst->getNextNode();
        while (llvm::isa<llvm::PHINode>(ipoint)) {
          ipoint = ipoint->getNextNode();
        }
        llvm::IRBuilder<> sub_ir(ipoint);
        rhs = GetPointer(program, module, sub_ir, rhs_inst, elem_type,
                         addr_space);

      } else {
        return GetPointerFromInt(ir, addr, elem_type, addr_space);
      }
    }

    addr_space = GetPointerAddressSpace(lhs, addr_space);
    addr_space = GetPointerAddressSpace(rhs, addr_space);
    dest_type = llvm::PointerType::get(elem_type, addr_space);

    if (lhs && rhs) {
      const auto bb = ir.GetInsertBlock();

      LOG(ERROR) << "Two pointers " << remill::LLVMThingToString(lhs) << " and "
                 << remill::LLVMThingToString(rhs) << " are added together "
                 << remill::LLVMThingToString(addr) << " in block "
                 << bb->getName().str() << " in function "
                 << bb->getParent()->getName().str();

      return ir.CreateIntToPtr(addr, dest_type);
    }

    if (rhs) {
      return GetIndexedPointer(program, module, ir, rhs, lhs_op, dest_type,
                               addr_space);

    } else {
      return GetIndexedPointer(program, module, ir, lhs, rhs_op, dest_type,
                               addr_space);
    }

  } else if (auto as_sub = llvm::dyn_cast<llvm::SubOperator>(addr); as_sub) {
    const auto lhs_op = as_sub->getOperand(0);
    const auto rhs_op = as_sub->getOperand(1);
    const auto rhs = llvm::dyn_cast<llvm::ConstantInt>(rhs_op);
    const auto lhs = FindPointer(ir, lhs_op, elem_type, addr_space);
    if (!lhs || !rhs) {
      return ir.CreateIntToPtr(addr, dest_type);

    } else {
      auto i32_ty = llvm::Type::getInt32Ty(addr->getContext());
      auto neg_index =
          static_cast<int64_t>(-static_cast<int32_t>(rhs->getZExtValue()));
      auto const_index = llvm::ConstantInt::get(
          i32_ty, static_cast<uint64_t>(neg_index), true);
      addr_space = GetPointerAddressSpace(lhs, addr_space);
      dest_type = llvm::PointerType::get(elem_type, addr_space);
      return GetIndexedPointer(program, module, ir, lhs, const_index, dest_type,
                               addr_space);
    }

  } else if (auto as_bc = llvm::dyn_cast<llvm::BitCastOperator>(addr); as_bc) {
    return GetPointer(program, module, ir, as_bc->getOperand(0), elem_type,
                      addr_space);

  // E.g. loading an address-sized integer register.
  } else if (addr_type->isIntegerTy()) {
    const auto bb = ir.GetInsertBlock();
    const auto addr_inst = &*ir.GetInsertPoint();

    // Go see if we can find multiple uses of `addr` in the same block, such
    // that each use converts `addr` to a pointer. If so, go and re-use those
    // `inttoptr` conversions instead of adding new ones.
    for (auto user : addr->users()) {
      const auto inst_user = llvm::dyn_cast<llvm::IntToPtrInst>(user);
      if (!inst_user || inst_user == addr_inst ||
          inst_user->getParent() != bb) {
        continue;
      }

      for (auto next_inst = inst_user->getNextNode(); next_inst;
           next_inst = next_inst->getNextNode()) {
        DCHECK_EQ(next_inst->getParent(), bb);

        // We've found `addr_inst`, i.e. the address we're pointer that we're
        // try to compute follows a previous equivalent computation in the same
        // block, so we'll go take that one.
        if (next_inst == addr_inst) {
          return ir.CreateBitCast(inst_user, dest_type);
        }
      }

      // We found another computation of this pointer, but it follows
      // `addr_inst` in the block, so we'll move it to where we need it.
      inst_user->removeFromParent();
      inst_user->insertBefore(addr_inst);
      return ir.CreateBitCast(inst_user, dest_type);
    }
    return GetPointerFromInt(ir, addr, elem_type, addr_space);

  } else {
    CHECK(addr_type->isPointerTy());
    return ir.CreateBitCast(addr, dest_type);
  }
}


// Lower an anvill type function into an `inttoptr` instructions
static void ReplaceTypeOp(const Program &program, llvm::Module &module,
                          llvm::Function *func) {
  auto callers = remill::CallersOf(func);
  for (auto call_inst : callers) {

    // The type of the argument value is the type that remill lifted.
    auto arg_val = call_inst->getArgOperand(0);
    llvm::IRBuilder<> irb(call_inst);

    // Make sure we are accessing the return type, instead of the pure function type.
    // The return type is the inferred Binja type, which is what we want.
    llvm::Type *func_ret_type = func->getReturnType()->getPointerElementType();

    // Assuming that the addr value is supposed to be 0, and that arg_val is a subsitute for addr.
    llvm::Value *ptr =
        GetPointer(program, module, irb, arg_val, func_ret_type, 0);

    // The ptr value should be the return type of the function, which is the binary ninja type.
    // Replace the call with uses of this pointer value
    call_inst->replaceAllUsesWith(ptr);
  }
  // Clean up
  for (auto call_inst : callers) {
    call_inst->eraseFromParent();
  }
  RemoveFunction(func);
}

static void LowerTypeOps(const Program &program, llvm::Module &mod) {
  std::vector<llvm::Function *> funcs;
  for (auto &func : mod) {
    funcs.push_back(&func);
  }
  for (auto func : funcs) {
    if (func->hasName() && func->getName().startswith("__anvill_type")) {
      ReplaceTypeOp(program, mod, func);
    }
  }
}

}  // namespace

// Optimize a module. This can be a module with semantics code, lifted
// code, etc.
void OptimizeModule(const EntityLifter &lifter_context,
                    const remill::Arch *arch, const Program &program,
                    llvm::Module &module) {

  if (auto err = module.materializeAll(); remill::IsError(err)) {
    LOG(FATAL) << remill::GetErrorString(err);
  }

  if (auto used = module.getGlobalVariable("llvm.used"); used) {
    used->setLinkage(llvm::GlobalValue::PrivateLinkage);
    used->eraseFromParent();
  }

  LOG(INFO) << "Optimizing module.";

  if (auto memory_escape = module.getFunction("__anvill_memory_escape")) {
    for (auto call : remill::CallersOf(memory_escape)) {
      call->eraseFromParent();
    }
    memory_escape->eraseFromParent();
  }

  llvm::legacy::PassManager mpm;
  mpm.add(llvm::createFunctionInliningPass(250));
  mpm.add(llvm::createGlobalOptimizerPass());
  mpm.add(llvm::createGlobalDCEPass());
  mpm.add(llvm::createStripDeadDebugInfoPass());
  mpm.run(module);

  llvm::legacy::FunctionPassManager fpm(&module);
  fpm.add(llvm::createEarlyCSEPass(true));
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createConstantPropagationPass());
  fpm.add(llvm::createSinkingPass());
  fpm.add(llvm::createNewGVNPass());
  fpm.add(llvm::createSCCPPass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createSROAPass());
  fpm.add(llvm::createPromoteMemoryToRegisterPass());
  fpm.add(llvm::createBitTrackingDCEPass());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createSinkingPass());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createInstructionCombiningPass());

  fpm.doInitialization();
  for (auto &func : module) {
    fpm.run(func);
  }
  fpm.doFinalization();

  RecoverStackMemoryAccesses(lifter_context, program, module);
  RecoverMemoryAccesses(lifter_context, program, module);

  std::unordered_set<llvm::Function *> changed_funcs;

  // We can remove these when they are not used.
  RemoveUnusedCalls(module, "fpclassify", changed_funcs);
  RemoveUnusedCalls(module, "__fpclassifyd", changed_funcs);
  RemoveUnusedCalls(module, "__fpclassifyf", changed_funcs);
  RemoveUnusedCalls(module, "__fpclassifyld", changed_funcs);

  // TODO(pag):
  // IN-PROGRESS: As code in this file is converted to passes, move it here.
  do {
    llvm::legacy::FunctionPassManager transforms(&module);
    transforms.add(CreateLowerRemillMemoryAccessIntrinsics());

    transforms.doInitialization();
    for (auto &func : module) {
      transforms.run(func);
    }
    transforms.doFinalization();
  } while (false);


  LowerTypeOps(program, module);

  RecoverMemoryReferences(program, module);

  fpm.doInitialization();
  for (auto &func : module) {
    fpm.run(func);
  }
  fpm.doFinalization();

  RemoveUnneededInlineAsm(program, module);

  mpm.run(module);

  RemoveUndefFuncCalls(module);

  CHECK(remill::VerifyModule(&module));
}

}  // namespace anvill
