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

#include "anvill/MCToIRLifter.h"

#include <glog/logging.h>

#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <new>
#include <set>
#include <type_traits>

#include "anvill/Decl.h"
#include "anvill/Program.h"
#include "anvill/Lift.h"

namespace anvill {
namespace {

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

}  // namespace

MCToIRLifter::MCToIRLifter(const remill::Arch *_arch, const Program &_program,
                           llvm::Module &_module)
    : arch(_arch),
      program(_program),
      module(_module),
      ctx(_module.getContext()),
      intrinsics(remill::IntrinsicTable(&_module)),
      inst_lifter(remill::InstructionLifter(_arch, &intrinsics)) {}

llvm::BasicBlock *MCToIRLifter::GetOrCreateBlock(const uint64_t addr) {
  auto &block = addr_to_block[addr];
  if (block) {
    return block;
  }

  std::stringstream ss;
  ss << "inst_" << std::hex << addr;
  block = llvm::BasicBlock::Create(ctx, ss.str(), lifted_func);

  // Missed an instruction?! This can happen when IDA merges two instructions
  // into one larger synthetic instruction. This might also be a tail-call.
  work_list.emplace(addr, curr_inst ? curr_inst->pc : 0);

  return block;
}

bool MCToIRLifter::DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                                         remill::Instruction *inst_out) {
  static const auto max_inst_size = arch->MaxInstructionSize();
  inst_out->Reset();

  auto byte = program.FindByte(addr);
  if (!byte.IsExecutable()) {
    return false;
  }

  // Read the bytes.
  auto &inst_bytes = inst_out->bytes;
  inst_bytes.reserve(max_inst_size);
  for (auto i = 0u; i < max_inst_size && byte && byte.IsExecutable();
       ++i, byte = program.FindNextByte(byte)) {
    auto maybe_val = byte.Value();
    if (remill::IsError(maybe_val)) {
      LOG(ERROR) << "Unable to read value of byte at " << std::hex
                 << byte.Address() << std::dec << ": "
                 << remill::GetErrorString(maybe_val);
      break;
    } else {
      inst_bytes.push_back(static_cast<char>(remill::GetReference(maybe_val)));
    }
  }

  if (is_delayed) {
    return arch->DecodeDelayedInstruction(addr, inst_out->bytes, *inst_out);
  } else {
    return arch->DecodeInstruction(addr, inst_out->bytes, *inst_out);
  }
}

void MCToIRLifter::VisitInvalid(const remill::Instruction &inst,
                                llvm::BasicBlock *block) {
  remill::AddTerminatingTailCall(block, intrinsics.error);
}

void MCToIRLifter::VisitError(const remill::Instruction &inst,
                              remill::Instruction *delayed_inst,
                              llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.error);
}

void MCToIRLifter::VisitNormal(const remill::Instruction &inst,
                               llvm::BasicBlock *block) {
  llvm::BranchInst::Create(GetOrCreateBlock(inst.next_pc), block);
}

void MCToIRLifter::VisitNoOp(const remill::Instruction &inst,
                             llvm::BasicBlock *block) {
  VisitNormal(inst, block);
}

void MCToIRLifter::VisitDirectJump(const remill::Instruction &inst,
                                   remill::Instruction *delayed_inst,
                                   llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc), block);
}

void MCToIRLifter::VisitIndirectJump(const remill::Instruction &inst,
                                     remill::Instruction *delayed_inst,
                                     llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.jump);
}

void MCToIRLifter::VisitFunctionReturn(const remill::Instruction &inst,
                                       remill::Instruction *delayed_inst,
                                       llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  llvm::ReturnInst::Create(ctx, remill::LoadMemoryPointer(block), block);
}

void MCToIRLifter::VisitDirectFunctionCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);

  if (auto decl = program.FindFunction(inst.branch_taken_pc); decl) {
    const auto entry = GetOrDeclareFunction(*decl);
    remill::AddCall(block, entry.lifted_to_native);
  } else {
    LOG(ERROR)
        << "Missing declaration for function at " << std::hex
        << inst.branch_taken_pc << " called at " << inst.pc << std::dec;
    remill::AddCall(block, intrinsics.function_call);
  }

  llvm::BranchInst::Create(GetOrCreateBlock(inst.next_pc), block);
}

void MCToIRLifter::VisitIndirectFunctionCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {

  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddCall(block, intrinsics.function_call);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.next_pc), block);
}

void MCToIRLifter::VisitConditionalBranch(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {

  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block = llvm::BasicBlock::Create(ctx, "", lifted_func);
  const auto not_taken_block = llvm::BasicBlock::Create(ctx, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_taken_pc),
                           taken_block);
  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

void MCToIRLifter::VisitAsyncHyperCall(const remill::Instruction &inst,
                                       remill::Instruction *delayed_inst,
                                       llvm::BasicBlock *block) {
  VisitDelayedInstruction(inst, delayed_inst, block, true);
  remill::AddTerminatingTailCall(block, intrinsics.async_hyper_call);
}

void MCToIRLifter::VisitConditionalAsyncHyperCall(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block) {
  VisitConditionalBranch(inst, delayed_inst, block);

  const auto lifted_func = block->getParent();
  const auto cond = remill::LoadBranchTaken(block);
  const auto taken_block = llvm::BasicBlock::Create(ctx, "", lifted_func);
  const auto not_taken_block = llvm::BasicBlock::Create(ctx, "", lifted_func);
  llvm::BranchInst::Create(taken_block, not_taken_block, cond, block);
  VisitDelayedInstruction(inst, delayed_inst, taken_block, true);
  VisitDelayedInstruction(inst, delayed_inst, not_taken_block, false);

  remill::AddTerminatingTailCall(taken_block, intrinsics.async_hyper_call);

  llvm::BranchInst::Create(GetOrCreateBlock(inst.branch_not_taken_pc),
                           not_taken_block);
}

void MCToIRLifter::VisitDelayedInstruction(
    const remill::Instruction &inst, remill::Instruction *delayed_inst,
    llvm::BasicBlock *block, bool on_taken_path) {
  if (delayed_inst &&
      arch->NextInstructionIsDelayed(inst, *delayed_inst, on_taken_path)) {
    inst_lifter.LiftIntoBlock(*delayed_inst, block, true);
  }
}

void MCToIRLifter::VisitInstruction(remill::Instruction &inst,
                                    llvm::BasicBlock *block) {
  curr_inst = &inst;

  std::aligned_storage<sizeof(remill::Instruction),
                       alignof(remill::Instruction)>
      delayed_inst_storage;

  remill::Instruction *delayed_inst = nullptr;

  // Even when something isn't supported or is invalid, we still lift
  // a call to a semantic, e.g.`INVALID_INSTRUCTION`, so we really want
  // to treat instruction lifting as an operation that can't fail.
  (void) inst_lifter.LiftIntoBlock(inst, block, false);

  if (arch->MayHaveDelaySlot(inst)) {
    delayed_inst = new (&delayed_inst_storage) remill::Instruction;
    if (!DecodeInstructionInto(inst.delayed_pc, true, delayed_inst)) {
      LOG(ERROR) << "Unable to decode or use delayed instruction at "
                 << std::hex << inst.delayed_pc << std::dec << " of "
                 << inst.Serialize();
    }
  }

  switch (inst.category) {
    case remill::Instruction::kCategoryInvalid:
      VisitInvalid(inst, block);
      break;
    case remill::Instruction::kCategoryError:
      VisitError(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryNormal:
      VisitNormal(inst, block);
      break;
    case remill::Instruction::kCategoryNoOp:
      VisitNoOp(inst, block);
      break;
    case remill::Instruction::kCategoryDirectJump:
      VisitDirectJump(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryIndirectJump:
      VisitIndirectJump(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryFunctionReturn:
      VisitFunctionReturn(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryDirectFunctionCall:
      VisitDirectFunctionCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryIndirectFunctionCall:
      VisitIndirectFunctionCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalBranch:
      VisitConditionalBranch(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryAsyncHyperCall:
      VisitAsyncHyperCall(inst, delayed_inst, block);
      break;
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      VisitConditionalAsyncHyperCall(inst, delayed_inst, block);
      break;
  }

  if (delayed_inst) {
    delayed_inst->~Instruction();
  }
}

// Declare the function decl `decl` and return an `llvm::Function *`.
MCToIRLifter::FunctionEntry
MCToIRLifter::GetOrDeclareFunction(const FunctionDecl &decl) {
  auto &entry = addr_to_func[decl.address];
  if (entry.lifted) {
    return entry;
  }

  const auto base_name = CreateFunctionName(decl.address);

  entry.lifted_to_native = remill::DeclareLiftedFunction(
      &module, base_name + ".lifted_to_native");

  entry.lifted = remill::DeclareLiftedFunction(
      &module, base_name + ".lifted");

  entry.native_to_lifted = decl.DeclareInModule(base_name, module, true);
  entry.native_to_lifted->removeFnAttr(llvm::Attribute::InlineHint);
  entry.native_to_lifted->removeFnAttr(llvm::Attribute::AlwaysInline);
  entry.native_to_lifted->addFnAttr(llvm::Attribute::NoInline);
  entry.lifted->setLinkage(llvm::GlobalValue::ExternalLinkage);

  return entry;
}

// Define the function that marshals native state to lifted state.
void MCToIRLifter::DefineNativeToLiftedWrapper(
    const FunctionDecl &decl, const FunctionEntry &entry) {
  const auto native_func = entry.native_to_lifted;
  const auto lifted_func = entry.lifted;

  // Set inlining attributes for lifted function
  lifted_func->removeFnAttr(llvm::Attribute::NoInline);
  lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);

  // Get module and context from the lifted function
  auto module = lifted_func->getParent();

  // Declare ABI-level function
  CHECK(native_func->isDeclaration());
  native_func->removeFnAttr(llvm::Attribute::InlineHint);
  native_func->removeFnAttr(llvm::Attribute::AlwaysInline);
  native_func->addFnAttr(llvm::Attribute::NoInline);

  // Get arch from the ABI-level function
  CHECK_EQ(arch->context, &ctx);

  // Create a state structure and a stack frame in the ABI-level function
  // and we'll call the lifted function with that. The lifted function
  // will get inlined into this function.
  auto block = llvm::BasicBlock::Create(ctx, "", native_func);
  llvm::IRBuilder<> ir(block);

  // Create a memory pointer.
  auto mem_ptr_type = remill::MemoryPointerType(module);
  llvm::Value *mem_ptr = llvm::Constant::getNullValue(mem_ptr_type);

  // Stack-allocate a state pointer.
  auto state_ptr_type = remill::StatePointerType(module);
  auto state_type = state_ptr_type->getElementType();
  auto state_ptr = ir.CreateAlloca(state_type);

//  // Get or create globals for all top-level registers. The idea here is that
//  // the spec could feasibly miss some dependencies, and so after optimization,
//  // we'll be able to observe uses of `__anvill_reg_*` globals, and handle
//  // them appropriately.
//  arch->ForEachRegister([=, &ir](const remill::Register *reg_) {
//    if (auto reg = reg_->EnclosingRegister(); reg_ == reg) {
//      std::stringstream ss;
//      ss << "__anvill_reg_" << reg->name;
//      const auto reg_name = ss.str();
//      auto reg_global = module->getGlobalVariable(reg_name);
//      if (!reg_global) {
//        reg_global = new llvm::GlobalVariable(
//            *module, reg->type, false, llvm::GlobalValue::ExternalLinkage,
//            nullptr, reg_name);
//      }
//      auto reg_ptr = reg->AddressOf(state_ptr, block);
//      ir.CreateStore(ir.CreateLoad(reg_global), reg_ptr);
//    }
//  });

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
      llvm::ConstantInt::get(pc_reg->type, decl.address, false));
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
  mem_ptr = StoreNativeValue(ret_addr, decl.return_address, intrinsics, block,
                             state_ptr, mem_ptr);

  // Store the function parameters either into the state struct
  // or into memory (likely the stack).
  auto arg_index = 0u;
  for (auto &arg : native_func->args()) {
    const auto &param_decl = decl.params[arg_index++];
    mem_ptr = StoreNativeValue(&arg, param_decl, intrinsics, block, state_ptr,
                               mem_ptr);
  }

  llvm::Value *lifted_func_args[remill::kNumBlockArgs] = {};
  lifted_func_args[remill::kStatePointerArgNum] = state_ptr;
  lifted_func_args[remill::kMemoryPointerArgNum] = mem_ptr;
  lifted_func_args[remill::kPCArgNum] = pc;
  auto call_to_lifted_func = ir.CreateCall(lifted_func, lifted_func_args);
  mem_ptr = call_to_lifted_func;

  llvm::Value *ret_val = nullptr;

  if (decl.returns.size() == 1) {
    ret_val = LoadLiftedValue(decl.returns.front(), intrinsics, block,
                              state_ptr, mem_ptr);
    ir.SetInsertPoint(block);

  } else if (1 < decl.returns.size()) {
    ret_val = llvm::UndefValue::get(native_func->getReturnType());
    auto index = 0u;
    for (auto &ret_decl : decl.returns) {
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
}

// Optimize a function.
static void OptimizeFunction(llvm::Function *func) {
  std::vector<llvm::CallInst *> calls_to_inline;
  for (auto changed = true; changed; changed = !calls_to_inline.empty()) {
    calls_to_inline.clear();

    for (auto &block : *func) {
      for (auto &inst : block) {
        if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst); call_inst) {
          if (auto called_func = call_inst->getCalledFunction();
              called_func &&
              !called_func->isDeclaration() &&
              !called_func->hasFnAttribute(llvm::Attribute::NoInline)) {
            calls_to_inline.push_back(call_inst);
          }
        }
      }
    }

    for (auto call_inst : calls_to_inline) {
      llvm::InlineFunctionInfo info;
      llvm::InlineFunction(call_inst, info);
    }
  }

  // Initialize cleanup optimizations
  llvm::legacy::FunctionPassManager fpm(func->getParent());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createPromoteMemoryToRegisterPass());
  fpm.add(llvm::createReassociatePass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createSROAPass());
  fpm.doInitialization();
  fpm.run(*func);
  fpm.doFinalization();

  ClearVariableNames(func);
}

// Define a function that marshals lifted state to native state.
void MCToIRLifter::DefineLiftedToNativeWrapper(
    const FunctionDecl &decl, const FunctionEntry &entry) {
  const auto lifted_func = entry.lifted_to_native;
  CHECK(lifted_func->isDeclaration());

  remill::CloneBlockFunctionInto(lifted_func);
  lifted_func->removeFnAttr(llvm::Attribute::NoInline);
  lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);
  lifted_func->setLinkage(llvm::GlobalValue::InternalLinkage);

  auto mem_ptr = remill::NthArgument(lifted_func, remill::kMemoryPointerArgNum);
  auto state_ptr = remill::NthArgument(lifted_func, remill::kStatePointerArgNum);
  auto block = &(lifted_func->getEntryBlock());

  llvm::IRBuilder<> ir(block);
  auto new_mem_ptr = decl.CallFromLiftedBlock(
      CreateFunctionName(decl.address), intrinsics, block, state_ptr,
      mem_ptr, true);

  ir.CreateRet(new_mem_ptr);
}

llvm::Function *MCToIRLifter::LiftFunction(const FunctionDecl &decl) {
  const auto entry = GetOrDeclareFunction(decl);
  if (!entry.native_to_lifted->isDeclaration()) {
    return entry.native_to_lifted;
  }

  work_list.clear();
  addr_to_block.clear();

  lifted_func = entry.lifted;
  CHECK(lifted_func->isDeclaration());

  remill::CloneBlockFunctionInto(lifted_func);
  lifted_func->removeFnAttr(llvm::Attribute::NoInline);
  lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);
  lifted_func->setLinkage(llvm::GlobalValue::InternalLinkage);

  // Add a branch between the first block of the lifted function, which sets
  // up some local variables, and the block that will contain the lifted
  // instruction.
  //
  // NOTE(pag): This also introduces the first element to the work list.
  llvm::BranchInst::Create(GetOrCreateBlock(decl.address),
                           &(lifted_func->getEntryBlock()));

  remill::Instruction inst;

  // Recursively decode and lift
  while (!work_list.empty()) {
    const auto ent = *(work_list.begin());
    work_list.erase(ent);
    const auto inst_addr = ent.first;
    const auto from_addr = ent.second;

    const auto block = addr_to_block[inst_addr];
    CHECK_NOTNULL(block);

    if (!block->empty()) {
      continue;  // Already handled.
    }

    // First, try to see if it's actually related to another function. This is
    // equivalent to a tail-call in the original code.
    if (auto other_decl = program.FindFunction(inst_addr);
        other_decl && inst_addr != other_decl->address) {
      const auto other_entry = GetOrDeclareFunction(decl);
      remill::AddTerminatingTailCall(block, other_entry.lifted_to_native);
      continue;
    }

    // Decode.
    if (!DecodeInstructionInto(inst_addr, false  /* is_delayed */, &inst)) {
      LOG(ERROR)
          << "Could not decode instruction at " << std::hex << inst_addr
          << " reachable from instruction " << from_addr
          << " in function at " << decl.address << std::dec;
      remill::AddTerminatingTailCall(block, intrinsics.error);
      continue;

    // Didn't get a valid instruction.
    } else if (!inst.IsValid() || inst.IsError()) {
      remill::AddTerminatingTailCall(block, intrinsics.error);
      continue;

    } else {
      VisitInstruction(inst, block);
    }
  }

  DefineNativeToLiftedWrapper(decl, entry);
  DefineLiftedToNativeWrapper(decl, entry);

  OptimizeFunction(entry.native_to_lifted);
  return entry.native_to_lifted;
}

}  // namespace anvill
