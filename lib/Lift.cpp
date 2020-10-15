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

#include "anvill/Lift.h"

#include <glog/logging.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/BC/Util.h>

#include "anvill/Decl.h"
#include "anvill/MCToIRLifter.h"
#include "anvill/Program.h"

namespace anvill {

namespace {

static std::string CreateFunctionName(uint64_t addr) {
  std::stringstream ss;
  ss << "sub_" << std::hex << addr;
  return ss.str();
}

// Adapt `src` to another type (likely an integer type) that is `dest_type`.
static llvm::Value *AdaptToType(llvm::IRBuilder<> &ir, llvm::Value *src,
                                llvm::Type *dest_type) {
  const auto src_type = src->getType();
  if (src_type == dest_type) {
    return src;
  }

  if (src_type->isIntegerTy()) {
    if (dest_type->isIntegerTy()) {
      auto src_size = src_type->getPrimitiveSizeInBits();
      auto dest_size = dest_type->getPrimitiveSizeInBits();
      if (src_size < dest_size) {
        return ir.CreateZExt(src, dest_type);
      } else {
        return ir.CreateTrunc(src, dest_type);
      }

    } else if (auto dest_ptr_type =
                   llvm::dyn_cast<llvm::PointerType>(dest_type);
               dest_ptr_type) {
      auto inter_type =
          llvm::PointerType::get(dest_ptr_type->getElementType(), 0);

      llvm::Value *inter_val = nullptr;
      if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(src); pti) {
        src = llvm::cast<llvm::Constant>(pti->getOperand(0));
        if (src->getType() == dest_type) {
          return src;
        } else {
          inter_val = ir.CreateBitCast(src, inter_type);
        }

      } else {
        inter_val = ir.CreateIntToPtr(src, inter_type);
      }

      if (inter_type == dest_ptr_type) {
        return inter_val;
      } else {
        return ir.CreateAddrSpaceCast(inter_val, dest_ptr_type);
      }
    }

  } else if (auto src_ptr_type = llvm::dyn_cast<llvm::PointerType>(src_type);
             src_ptr_type) {

    // Cast the pointer to the other pointer type.
    if (auto dest_ptr_type = llvm::dyn_cast<llvm::PointerType>(dest_type);
        dest_ptr_type) {

      if (src_ptr_type->getAddressSpace() != dest_ptr_type->getAddressSpace()) {
        src_ptr_type = llvm::PointerType::get(src_ptr_type->getElementType(),
                                              dest_ptr_type->getAddressSpace());
        src = ir.CreateAddrSpaceCast(src, src_ptr_type);
      }

      if (src_ptr_type == dest_ptr_type) {
        return src;
      } else {
        return ir.CreateBitCast(src, dest_ptr_type);
      }

    // Convert the pointer to an integer.
    } else if (auto dest_int_type =
                   llvm::dyn_cast<llvm::IntegerType>(dest_type);
               dest_int_type) {
      if (src_ptr_type->getAddressSpace()) {
        src_ptr_type =
            llvm::PointerType::get(src_ptr_type->getElementType(), 0);
        src = ir.CreateAddrSpaceCast(src, src_ptr_type);
      }

      const auto block = ir.GetInsertBlock();
      const auto func = block->getParent();
      const auto module = func->getParent();
      const auto &dl = module->getDataLayout();
      auto &context = module->getContext();
      src = ir.CreatePtrToInt(
          src, llvm::Type::getIntNTy(context, dl.getPointerSizeInBits(0)));
      return AdaptToType(ir, src, dest_type);
    }

  } else if (src_type->isFloatTy()) {
    if (dest_type->isDoubleTy()) {
      return ir.CreateFPExt(src, dest_type);

    } else if (dest_type->isIntegerTy()) {
      const auto i32_type = llvm::Type::getInt32Ty(dest_type->getContext());
      return AdaptToType(ir, ir.CreateBitCast(src, i32_type), dest_type);
    }

  } else if (src_type->isDoubleTy()) {
    if (dest_type->isFloatTy()) {
      return ir.CreateFPTrunc(src, dest_type);

    } else if (dest_type->isIntegerTy()) {
      const auto i64_type = llvm::Type::getInt64Ty(dest_type->getContext());
      return AdaptToType(ir, ir.CreateBitCast(src, i64_type), dest_type);
    }
  }

  // Fall-through, we don't have a supported adaptor.
  return nullptr;
}

// Clear out LLVM variable names. They're usually not helpful.
static void ClearVariableNames(llvm::Function *func) {
  for (auto &block : *func) {
    block.setName("");
    for (auto &inst : block) {
      if (inst.hasName()) {
        inst.setName("");
      }
    }
  }
}

// A function that ensures that the memory pointer escapes, and thus none of
// the memory writes at the end of a function are lost.
static llvm::Function *
GetMemoryEscapeFunc(const remill::IntrinsicTable &intrinsics) {
  auto module = intrinsics.error->getParent();
  auto &context = module->getContext();

  auto name = "__anvill_memory_escape";
  if (auto func = module->getFunction(name)) {
    return func;
  }

  llvm::Type *params[] = {
      remill::NthArgument(intrinsics.error, remill::kMemoryPointerArgNum)
          ->getType()};
  auto type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), params, false);
  return llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, name,
                                module);
}

// Create an adaptor function that converts lifted state to native state.
// This function is marked as always-inline so that when a lifted function
// calls this function, it ends up doing so in a way that, post-optimization,
// ends up calling the higher-level function.
static llvm::Function *
CreateLiftedToABIAdaptor(const std::string &name,
                         const remill::IntrinsicTable &intrinsics,
                         const anvill::FunctionDecl *decl) {

  std::stringstream ss;
  ss << name << ".anvill.lifted_to_native";
  auto lifted_name = ss.str();
  auto module = intrinsics.error->getParent();
  auto adaptor = remill::DeclareLiftedFunction(module, lifted_name);

  if (!adaptor->isDeclaration()) {
    return adaptor;  // Already defined.
  }

  // Declare all registers in that function. Makes life easier.
  remill::CloneBlockFunctionInto(adaptor);

  auto block = &(adaptor->getEntryBlock());
  auto state_ptr = remill::LoadStatePointer(block);
  auto mem_ptr = remill::LoadMemoryPointer(block);
  auto new_mem_ptr =
      decl->CallFromLiftedBlock(name, intrinsics, block, state_ptr, mem_ptr);

  llvm::IRBuilder<> ir(block);
  ir.CreateRet(new_mem_ptr);

  adaptor->removeFnAttr(llvm::Attribute::NoInline);
  adaptor->addFnAttr(llvm::Attribute::InlineHint);
  adaptor->addFnAttr(llvm::Attribute::AlwaysInline);
  adaptor->setLinkage(llvm::GlobalValue::PrivateLinkage);

  return adaptor;
}

static void ReplaceLiftedCalls(const FunctionDecl *decl,
                               llvm::Function *lifted_func) {

  // Create adaptor function
  remill::IntrinsicTable intrinsics(lifted_func->getParent());
  auto name = CreateFunctionName(decl->address);
  auto adaptor = CreateLiftedToABIAdaptor(name, intrinsics, decl);

  // Replace calls
  for (auto call : remill::CallersOf(lifted_func)) {
    call->setCalledFunction(adaptor);
  }
}

static void DefineABIFunction(const FunctionDecl *decl,
                              llvm::Function *lifted_func) {

  // Set inlining attributes for lifted function
  lifted_func->removeFnAttr(llvm::Attribute::NoInline);
  lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);

  // Get module and context from the lifted function
  auto module = lifted_func->getParent();
  auto &ctx = module->getContext();

  // Declare ABI-level function
  auto abi_func = decl->DeclareInModule(CreateFunctionName(decl->address), *module);

  // Get arch from the ABI-level function
  auto arch = decl->arch;
  CHECK_EQ(arch->context, &ctx);

  // Create a state structure and a stack frame in the ABI-level function
  // and we'll call the lifted function with that. The lifted function
  // will get inlined into this function.
  auto block = llvm::BasicBlock::Create(ctx, "", abi_func);
  llvm::IRBuilder<> ir(block);

  // Create a memory pointer.
  auto mem_ptr_type = remill::MemoryPointerType(module);
  llvm::Value *mem_ptr = llvm::Constant::getNullValue(mem_ptr_type);

  // Stack-allocate a state pointer.
  auto state_ptr_type = remill::StatePointerType(module);
  auto state_type = state_ptr_type->getElementType();
  auto state_ptr = ir.CreateAlloca(state_type);

  // Get or create globals for all top-level registers. The idea here is that
  // the spec could feasibly miss some dependencies, and so after optimization,
  // we'll be able to observe uses of `__anvill_reg_*` globals, and handle
  // them appropriately.
  // arch->ForEachRegister([=, &ir](const remill::Register *reg_) {
  //   if (auto reg = reg_->EnclosingRegister(); reg_ == reg) {
  //     std::stringstream ss;
  //     ss << "__anvill_reg_" << reg->name;
  //     const auto reg_name = ss.str();
  //     auto reg_global = module->getGlobalVariable(reg_name);
  //     if (!reg_global) {
  //       reg_global = new llvm::GlobalVariable(
  //           *module, reg->type, false, llvm::GlobalValue::ExternalLinkage,
  //           nullptr, reg_name);
  //     }
  //     auto reg_ptr = reg->AddressOf(state_ptr, block);
  //     ir.CreateStore(ir.CreateLoad(reg_global), reg_ptr);
  //   }
  // });

  // Store the program counter into the state.
  auto pc_reg = arch->RegisterByName(arch->ProgramCounterRegisterName());
  auto pc_reg_ptr = pc_reg->AddressOf(state_ptr, block);

  auto base_pc = module->getGlobalVariable("__anvill_pc");
  if (!base_pc) {
    base_pc = new llvm::GlobalVariable(
        *module, llvm::Type::getInt8Ty(ctx), false,
        llvm::GlobalValue::ExternalLinkage, nullptr, "__anvill_pc");
  }

  auto pc = llvm::ConstantExpr::getAdd(
      llvm::ConstantExpr::getPtrToInt(base_pc, pc_reg->type),
      llvm::ConstantInt::get(pc_reg->type, decl->address, false));
  ir.SetInsertPoint(block);
  ir.CreateStore(pc, pc_reg_ptr);

  // Initialize the stack pointer.
  auto sp_reg = arch->RegisterByName(arch->StackPointerRegisterName());
  auto sp_reg_ptr = sp_reg->AddressOf(state_ptr, block);

  auto base_sp = module->getGlobalVariable("__anvill_sp");
  if (!base_sp) {
    base_sp = new llvm::GlobalVariable(
        *module, llvm::Type::getInt8Ty(ctx), false,
        llvm::GlobalValue::ExternalLinkage, nullptr, "__anvill_sp");
  }

  auto sp = llvm::ConstantExpr::getPtrToInt(base_sp, sp_reg->type);
  ir.SetInsertPoint(block);
  ir.CreateStore(sp, sp_reg_ptr);

  // Put the function's return address wherever it needs to go.
  auto base_ra = module->getGlobalVariable("__anvill_ra");
  if (!base_ra) {
    base_ra = new llvm::GlobalVariable(
        *module, llvm::Type::getInt8Ty(ctx), false,
        llvm::GlobalValue::ExternalLinkage, nullptr, "__anvill_ra");
  }

  auto ret_addr = llvm::ConstantExpr::getPtrToInt(base_ra, pc_reg->type);

  remill::IntrinsicTable intrinsics(module);
  mem_ptr = StoreNativeValue(ret_addr, decl->return_address, intrinsics, block,
                             state_ptr, mem_ptr);

  // Store the function parameters either into the state struct
  // or into memory (likely the stack).
  auto arg_index = 0u;
  for (auto &arg : abi_func->args()) {
    const auto &param_decl = decl->params[arg_index++];
    mem_ptr = StoreNativeValue(&arg, param_decl, intrinsics, block, state_ptr,
                               mem_ptr);
  }

  // Create a call to ABI to lifted function
  llvm::Value *lifted_func_args[remill::kNumBlockArgs] = {};
  lifted_func_args[remill::kStatePointerArgNum] = state_ptr;
  lifted_func_args[remill::kMemoryPointerArgNum] = mem_ptr;
  lifted_func_args[remill::kPCArgNum] = pc;
  auto call_to_lifted_func = ir.CreateCall(lifted_func, lifted_func_args);
  mem_ptr = call_to_lifted_func;

  // Retrieve return values from lifted function
  llvm::Value *ret_val = nullptr;
  if (decl->returns.size() == 1) {
    ret_val = LoadLiftedValue(decl->returns.front(), intrinsics, block,
                              state_ptr, mem_ptr);
    ir.SetInsertPoint(block);

  } else if (1 < decl->returns.size()) {
    ret_val = llvm::UndefValue::get(abi_func->getReturnType());
    auto index = 0u;
    for (auto &ret_decl : decl->returns) {
      auto partial_ret_val =
          LoadLiftedValue(ret_decl, intrinsics, block, state_ptr, mem_ptr);
      ir.SetInsertPoint(block);
      unsigned indexes[] = {index};
      ret_val = ir.CreateInsertValue(ret_val, partial_ret_val, indexes);
      index += 1;
    }
  }

  auto memory_escape = GetMemoryEscapeFunc(intrinsics);
  llvm::Value *escape_args[] = {mem_ptr};
  ir.CreateCall(memory_escape, escape_args);

  if (ret_val) {
    ir.CreateRet(ret_val);
  } else {
    ir.CreateRetVoid();
  }

  llvm::InlineFunctionInfo info;
  llvm::InlineFunction(call_to_lifted_func, info);

  std::vector<llvm::CallInst *> calls_to_inline;
  for (auto &block : *abi_func) {
    for (auto &inst : block) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        calls_to_inline.push_back(call_inst);
      }
    }
  }

  for (auto call_inst : calls_to_inline) {
    llvm::InlineFunctionInfo info;
    llvm::InlineFunction(call_inst, info);
  }

  ClearVariableNames(abi_func);
}
}  // namespace

// Produce one or more instructions in `in_block` to store the
// native value `native_val` into the lifted state associated
// with `decl`.
llvm::Value *StoreNativeValue(llvm::Value *native_val, const ValueDecl &decl,
                              const remill::IntrinsicTable &intrinsics,
                              llvm::BasicBlock *in_block,
                              llvm::Value *state_ptr, llvm::Value *mem_ptr) {

  auto func = in_block->getParent();
  auto module = func->getParent();

  CHECK_EQ(module, intrinsics.read_memory_8->getParent());
  CHECK_EQ(native_val->getType(), decl.type);

  // Store it to a register.
  if (decl.reg) {
    auto ptr_to_reg = decl.reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    if (decl.type != decl.reg->type) {
      ir.CreateStore(llvm::Constant::getNullValue(decl.reg->type), ptr_to_reg);
    }

    if (auto adapted_val = AdaptToType(ir, native_val, decl.reg->type);
        adapted_val) {
      ir.CreateStore(adapted_val, ptr_to_reg);

    } else {
      ir.CreateStore(
          native_val,
          ir.CreateBitCast(ptr_to_reg, llvm::PointerType::get(decl.type, 0)));
    }

    return mem_ptr;

  // Store it to memory.
  } else if (decl.mem_reg) {
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, in_block);

    llvm::IRBuilder<> ir(in_block);
    const auto addr = ir.CreateAdd(
        ir.CreateLoad(ptr_to_reg),
        llvm::ConstantInt::get(decl.mem_reg->type,
                               static_cast<uint64_t>(decl.mem_offset), true));
    return remill::StoreToMemory(intrinsics, in_block, native_val, mem_ptr,
                                 addr);

  } else {
    return llvm::UndefValue::get(mem_ptr->getType());
  }
}

llvm::Value *LoadLiftedValue(const ValueDecl &decl,
                             const remill::IntrinsicTable &intrinsics,
                             llvm::BasicBlock *in_block, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr) {

  auto func = in_block->getParent();
  auto module = func->getParent();

  CHECK_EQ(module, intrinsics.read_memory_8->getParent());

  // Load it out of a register.
  if (decl.reg) {
    auto ptr_to_reg = decl.reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    auto reg = ir.CreateLoad(ptr_to_reg);
    if (auto adapted_val = AdaptToType(ir, reg, decl.type)) {
      return adapted_val;
    } else {
      return ir.CreateLoad(
          ir.CreateBitCast(ptr_to_reg, llvm::PointerType::get(decl.type, 0)));
    }

  // Load it out of memory.
  } else if (decl.mem_reg) {
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    const auto addr = ir.CreateAdd(
        ir.CreateLoad(ptr_to_reg),
        llvm::ConstantInt::get(decl.mem_reg->type,
                               static_cast<uint64_t>(decl.mem_offset), true));
    return llvm::dyn_cast<llvm::Instruction>(
        remill::LoadFromMemory(intrinsics, in_block, decl.type, mem_ptr, addr));

  } else {
    return llvm::UndefValue::get(decl.type);
  }
}

bool LiftCodeIntoModule(const remill::Arch *arch, const Program &program,
                        llvm::Module &module) {
  DLOG(INFO) << "LiftCodeIntoModule";

  // Initialize cleanup optimizations
  llvm::legacy::FunctionPassManager fpm(&module);
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createPromoteMemoryToRegisterPass());
  fpm.add(llvm::createReassociatePass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.doInitialization();

  // Create our lifter
  MCToIRLifter lifter(arch, program, module);

  // Declare global variables
  program.ForEachVariable([&](const anvill::GlobalVarDecl *decl) {
    std::stringstream ss;
    ss << "data_" << std::hex << decl->address << std::dec;
    decl->DeclareInModule(ss.str(), module);
    return true;
  });

  // Forward declare lifted functions
  program.ForEachFunction([&](const FunctionDecl *decl) {
    lifter.GetOrDeclareFunction(decl->address);
    return true;
  });

  // Lift functions
  program.ForEachFunction([&](const FunctionDecl *decl) {
    lifter.GetOrDefineFunction(decl->address);
    return true;
  });

  // Replace calls to lifted functions with calls to ABI-level functions
  program.ForEachFunction([&](const FunctionDecl *decl) {
    auto func = lifter.GetOrDeclareFunction(decl->address);
    ReplaceLiftedCalls(decl, func);
    return true;
  });


  // Define ABI-level functions
  program.ForEachFunction([&](const FunctionDecl *decl) {
    auto func = lifter.GetOrDeclareFunction(decl->address);
    fpm.run(*func);
    DefineABIFunction(decl, func);
    return true;
  });

  // Verify the module
  CHECK(remill::VerifyModule(&module));

  // Done
  fpm.doFinalization();
  return true;
}

}  // namespace anvill
