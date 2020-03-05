/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <unordered_set>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Local.h>

#include <remill/BC/ABI.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>

#include "anvill/Decl.h"
#include "anvill/Program.h"

namespace anvill {
namespace {

// Looks for calls to a function like `__remill_function_return`, and
// replace its state pointer with a null pointer so that the state
// pointer never escapes.
static void MuteStateEscape(
    llvm::Module &module, const char *func_name,
    std::unordered_set<llvm::Function *> &changed_funcs) {
  auto func = module.getFunction(func_name);
  if (!func) {
    return;
  }

  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      auto arg_op = call_inst->getArgOperand(remill::kStatePointerArgNum);
      call_inst->setArgOperand(
          remill::kStatePointerArgNum,
          llvm::UndefValue::get(arg_op->getType()));

      auto in_block = call_inst->getParent();
      auto in_func = in_block->getParent();
      changed_funcs.insert(in_func);
    }
  }
}

// Used to remove the calls to functions that don't really have a big
// side-effect, but which Clang can't just remove because it can't be
// sure, e.g. `fpclassify`.
static void RemoveUnusedCalls(
    llvm::Module &module, const char *func_name,
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

// Remove calls to memory read functions that have undefined
// addresses.
static void RemoveUndefMemoryReads(
    llvm::Module &module, const char *func_name,
    std::unordered_set<llvm::Function *> &changed_funcs) {
  auto func = module.getFunction(func_name);
  if (!func) {
    return;
  }

  std::vector<llvm::CallInst *> to_remove;

  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      auto addr = call_inst->getArgOperand(1);
      if (llvm::isa<llvm::UndefValue>(addr)) {
        call_inst->replaceAllUsesWith(llvm::UndefValue::get(
            call_inst->getType()));
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

// Remove calls to memory write functions that have undefined addresses
// or undefined values.
static void RemoveUndefMemoryWrites(
    llvm::Module &module, const char *func_name,
    std::unordered_set<llvm::Function *> &changed_funcs) {
  auto func = module.getFunction(func_name);
  if (!func) {
    return;
  }

  std::vector<llvm::CallInst *> to_remove;

  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      auto mem_ptr = call_inst->getArgOperand(0);
      auto addr = call_inst->getArgOperand(1);
      auto val = call_inst->getArgOperand(2);
      if (llvm::isa<llvm::UndefValue>(addr)) {
        call_inst->replaceAllUsesWith(mem_ptr);
        to_remove.push_back(call_inst);

      } else if (llvm::isa<llvm::UndefValue>(val)) {
        call_inst->replaceAllUsesWith(mem_ptr);
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

// Look for reads of constant memory locations, and replace
// with the values that would have been read.
static void ReplaceConstMemoryReads(
    const Program &program, llvm::Module &module,
    const char *func_name,
    std::unordered_set<llvm::Function *> &changed_funcs,
    llvm::Type *fp80_type=nullptr) {

  auto func = module.getFunction(func_name);
  if (!func) {
    return;
  }

  std::vector<llvm::CallInst *> to_remove;

  auto &context = module.getContext();
  llvm::DataLayout dl(&module);
  std::vector<uint8_t> bytes;

  for (auto user : func->users()) {
    auto call_inst = llvm::dyn_cast<llvm::CallInst>(user);
    if (!call_inst) {
      continue;
    }

    auto addr_val = call_inst->getArgOperand(1);
    auto addr_const = llvm::dyn_cast<llvm::ConstantInt>(addr_val);
    if (!addr_const) {
      continue;
    }

    const auto addr = addr_const->getZExtValue();
    auto mem_type = fp80_type ? fp80_type : call_inst->getType();
    auto ret_val_size = dl.getTypeAllocSize(mem_type);
    bytes.reserve(ret_val_size);

    for (size_t i = 0; i< ret_val_size; ++i) {
      auto byte = program.FindByte(addr);
      if (byte && byte.IsReadable() && !byte.IsWriteable()) {
        bytes.push_back(*byte.Value());
      } else {
        bytes.clear();
        break;
      }
    }

    if (bytes.empty()) {
      continue;
    }

    const auto parent_func = call_inst->getParent()->getParent();
    changed_funcs.insert(parent_func);

    auto entry_block = &(parent_func->getEntryBlock());
    llvm::IRBuilder<> ir(entry_block);

    // Create a constant out of the bytes that would be read, then
    // alloca some space for it, store the bytes into the alloca,
    // and replace the call with the loaded result.
    auto data_read = llvm::ConstantDataArray::get(context, bytes);
    auto mem = ir.CreateAlloca(mem_type);
    auto bc = ir.CreateBitCast(
        mem, llvm::PointerType::get(data_read->getType(), 0));
    ir.CreateStore(data_read, bc);

    llvm::Instruction *as_load = new llvm::LoadInst(mem, "", call_inst);

    if (fp80_type) {
      as_load = new llvm::FPTruncInst(
          as_load, call_inst->getType(), "", call_inst);
    }

    call_inst->replaceAllUsesWith(as_load);
    to_remove.push_back(call_inst);
  }

  for (auto call_inst : to_remove) {
    call_inst->eraseFromParent();
  }
}

// Look for compiler barriers (empty inline asm statements marked
// with side-effects) and try to remove them. If we see some barriers
// bracketed by extern
static void RemoveUnneededInlineAsm(
    const Program &program, llvm::Module &module) {
  std::vector<llvm::CallInst *> to_remove;

  program.ForEachFunction([&] (const FunctionDecl *decl) -> bool {
    const auto func = decl->DeclareInModule(module);
    if (func->isDeclaration()) {
      return true;
    }

    to_remove.clear();

    for (auto &block : *func) {
      auto prev_is_compiler_barrier = false;
      llvm::CallInst *prev_barrier = nullptr;
      for (auto &inst : block) {
        if (llvm::CallInst *call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
          const auto inline_asm = llvm::dyn_cast<llvm::InlineAsm>(
              call_inst->getCalledValue());
          if (inline_asm) {
            if (inline_asm->hasSideEffects() &&
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

}  // namespace

// Optimize a module. This can be a module with semantics code, lifted
// code, etc.
void OptimizeModule(const remill::Arch *arch,
                    const Program &program,
                    llvm::Module &module) {
  auto &context = module.getContext();
  const auto fp80_type = llvm::Type::getX86_FP80Ty(context);

  std::vector<llvm::Function *> traces;

  if (auto bb_func = module.getFunction("__remill_basic_block")) {
    const auto bb_func_type = bb_func->getType();
    for (auto &func : module) {
      if (func.getType() == bb_func_type) {
        traces.push_back(&func);
      }
    }
  }

  if (traces.empty()) {
    remill::OptimizeBareModule(&module);
  } else {
    remill::OptimizeModule(arch, &module, traces);
  }

  std::unordered_set<llvm::Function *> changed_funcs;

  // These improve optimizability.
  MuteStateEscape(module, "__remill_function_return", changed_funcs);
  MuteStateEscape(module, "__remill_error", changed_funcs);
  MuteStateEscape(module, "__remill_missing_block", changed_funcs);

  // We can remove these when they are not used.
  RemoveUnusedCalls(module, "fpclassify", changed_funcs);
  RemoveUnusedCalls(module, "__fpclassifyd", changed_funcs);
  RemoveUnusedCalls(module, "__fpclassifyf", changed_funcs);
  RemoveUnusedCalls(module, "__fpclassifyld", changed_funcs);

  do {
    RemoveUndefMemoryReads(module, "__remill_read_memory_8", changed_funcs);
    RemoveUndefMemoryReads(module, "__remill_read_memory_16", changed_funcs);
    RemoveUndefMemoryReads(module, "__remill_read_memory_32", changed_funcs);
    RemoveUndefMemoryReads(module, "__remill_read_memory_64", changed_funcs);
    RemoveUndefMemoryReads(module, "__remill_read_memory_f32", changed_funcs);
    RemoveUndefMemoryReads(module, "__remill_read_memory_f64", changed_funcs);
    RemoveUndefMemoryReads(module, "__remill_read_memory_f80", changed_funcs);

    RemoveUndefMemoryWrites(module, "__remill_write_memory_8", changed_funcs);
    RemoveUndefMemoryWrites(module, "__remill_write_memory_16", changed_funcs);
    RemoveUndefMemoryWrites(module, "__remill_write_memory_32", changed_funcs);
    RemoveUndefMemoryWrites(module, "__remill_write_memory_64", changed_funcs);
    RemoveUndefMemoryWrites(module, "__remill_write_memory_f32", changed_funcs);
    RemoveUndefMemoryWrites(module, "__remill_write_memory_f64", changed_funcs);
    RemoveUndefMemoryWrites(module, "__remill_write_memory_f80", changed_funcs);

    llvm::legacy::FunctionPassManager pm(&module);
    pm.add(llvm::createDeadCodeEliminationPass());
    pm.add(llvm::createSROAPass());
    pm.add(llvm::createPromoteMemoryToRegisterPass());

    for (auto func : changed_funcs) {
      pm.run(*func);
    }

    changed_funcs.clear();

    ReplaceConstMemoryReads(program, module, "__remill_read_memory_8", changed_funcs);
    ReplaceConstMemoryReads(program, module, "__remill_read_memory_16", changed_funcs);
    ReplaceConstMemoryReads(program, module, "__remill_read_memory_32", changed_funcs);
    ReplaceConstMemoryReads(program, module, "__remill_read_memory_64", changed_funcs);
    ReplaceConstMemoryReads(program, module, "__remill_read_memory_f32", changed_funcs);
    ReplaceConstMemoryReads(program, module, "__remill_read_memory_f64", changed_funcs);
    ReplaceConstMemoryReads(
        program, module, "__remill_read_memory_f80", changed_funcs,
        fp80_type);

  } while (!changed_funcs.empty());

  RemoveUnneededInlineAsm(program, module);
}

}  // namespace anvill
