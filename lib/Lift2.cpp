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

#include "anvill/Lift2.h"

#include <glog/logging.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <remill/BC/Util.h>

#include <set>

#include "anvill/Decl.h"
#include "anvill/Program.h"

namespace anvill {

FunctionLifter::FunctionLifter(const remill::Arch *_arch,
                               const Program &_program, llvm::Module &_module)
    : arch(_arch),
      program(_program),
      module(_module),
      ctx(_module.getContext()),
      intrinsics(remill::IntrinsicTable(&_module)),
      inst_lifter(remill::InstructionLifter(_arch, &intrinsics)) {}

llvm::BasicBlock *FunctionLifter::GetOrCreateBlock(const uint64_t addr,
                                                   llvm::Function *func) {
  auto &block = addr_to_block[addr];
  if (block) {
    return block;
  }

  std::stringstream ss;
  ss << "inst_" << std::hex << addr << std::dec;
  block = llvm::BasicBlock::Create(ctx, ss.str(), func);

  return block;
}

remill::Instruction FunctionLifter::DecodeInstruction(const uint64_t addr) {
  // Read
  auto bytes = program.FindBytes(addr, arch->MaxInstructionSize());
  CHECK(bytes) << "Failed reading instruction at address: " << std::hex << addr
               << std::dec;
  // Decode
  remill::Instruction inst;
  CHECK(arch->DecodeInstruction(addr, bytes.ToString(), inst))
      << "Failed decoding instruction at address: " << std::hex << addr
      << std::dec;

  return inst;
}

llvm::Function *FunctionLifter::LiftFunction(const uint64_t func_addr) {
  if (!addr_to_func.count(func_addr)) {
    LOG(WARNING) << "No declared function at address: " << std::hex << func_addr
                 << std::dec;
    return nullptr;
  }

  auto &func = addr_to_func[func_addr];
  if (!func->empty()) {
    LOG(WARNING) << "Asking to re-lift function: " << func->getName().str()
                 << "; returning current function instead";
    return func;
  }

  DLOG(INFO) << "Lifting function: " << func->getName().str();
  // Get `__remill_basic_block` into `func`
  remill::CloneBlockFunctionInto(func);
  // Lifting function attributes
  func->removeFnAttr(llvm::Attribute::NoReturn);
  func->removeFnAttr(llvm::Attribute::NoUnwind);
  func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  func->setLinkage(llvm::GlobalValue::ExternalLinkage);
  // Inlining function attributes
  func->removeFnAttr(llvm::Attribute::AlwaysInline);
  func->removeFnAttr(llvm::Attribute::InlineHint);
  func->addFnAttr(llvm::Attribute::NoInline);
  // Recursively decode and lift
  std::set<uint64_t> worklist({func_addr});
  while (!worklist.empty()) {
    auto inst_addr = *worklist.begin();
    worklist.erase(inst_addr);
    // Check if we already lifted `inst_addr`
    auto block = GetOrCreateBlock(inst_addr, func);
    if (!block->empty()) {
      continue;
    }
    // Decode
    auto inst = DecodeInstruction(inst_addr);
    // Lift into `block`
    DLOG(INFO) << "Lifting instruction: " << inst.Serialize();
    switch (inst_lifter.LiftIntoBlock(inst, block)) {
      case remill::kLiftedInstruction: {
      } break;

      case remill::kLiftedInvalidInstruction:
        LOG(FATAL) << "Asking to lift invalid instruction: "
                   << inst.Serialize();
        break;

      case remill::kLiftedUnsupportedInstruction:
        LOG(FATAL) << "Asking to lift unsupported instruction: "
                   << inst.Serialize();
        break;
    }
    // // Add successors of `inst` to the worklist
    llvm::IRBuilder<> ir(block);
    switch (inst.category) {
      case remill::Instruction::kCategoryInvalid: {
        LOG(FATAL) << "Asking to add successors of invalid instruction";
      } break;

      case remill::Instruction::kCategoryNormal:
      case remill::Instruction::kCategoryNoOp: {
        auto next_pc = inst.next_pc;
        worklist.insert(next_pc);
        ir.CreateBr(GetOrCreateBlock(next_pc, func));
      } break;

      case remill::Instruction::kCategoryError: break;

      case remill::Instruction::kCategoryDirectJump: {
        auto next_pc = inst.branch_taken_pc;
        worklist.insert(next_pc);
        ir.CreateBr(GetOrCreateBlock(next_pc, func));
      } break;

      case remill::Instruction::kCategoryIndirectJump: {
        remill::AddTerminatingTailCall(block, intrinsics.jump);
      } break;

      case remill::Instruction::kCategoryFunctionReturn: {
        ir.CreateRet(remill::LoadMemoryPointer(block));
      } break;

      case remill::Instruction::kCategoryDirectFunctionCall: {
        remill::AddCall(block, GetOrDeclareFunction(inst.branch_taken_pc));
        auto next_pc = inst.next_pc;
        worklist.insert(next_pc);
        ir.CreateBr(GetOrCreateBlock(next_pc, func));
      } break;

      case remill::Instruction::kCategoryIndirectFunctionCall: {
        remill::AddCall(block, intrinsics.function_call);
        auto next_pc = inst.next_pc;
        worklist.insert(next_pc);
        ir.CreateBr(GetOrCreateBlock(next_pc, func));
      } break;

      case remill::Instruction::kCategoryConditionalBranch: {
        auto true_pc = inst.branch_taken_pc;
        auto false_pc = inst.branch_not_taken_pc;
        worklist.insert(true_pc);
        worklist.insert(false_pc);
        ir.CreateCondBr(remill::LoadBranchTaken(block),
                        GetOrCreateBlock(true_pc, func),
                        GetOrCreateBlock(false_pc, func));
      } break;

      default: {
        LOG(FATAL) << "Unsupported instruction successor";
      } break;
    }
  }

  return func;
}

llvm::Function *FunctionLifter::GetOrDeclareFunction(const uint64_t addr) {
  auto &func = addr_to_func[addr];
  if (func) {
    return func;
  }

  std::stringstream ss;
  ss << "sub_" << std::hex << addr << std::dec;
  func = remill::DeclareLiftedFunction(&module, ss.str());

  return func;
}

bool FunctionLifter::DefineLiftedFunctions() {
  llvm::legacy::FunctionPassManager fpm(&module);
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createPromoteMemoryToRegisterPass());
  fpm.add(llvm::createReassociatePass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.doInitialization();

  for (auto [addr, func] : addr_to_func) {
    if (!func->empty()) {
      LOG(WARNING) << "Asking to re-lift function: " << func->getName().str()
                   << "; returning current function instead";
      continue;
    }

    auto lifted_func = LiftFunction(addr);
    if (!lifted_func) {
      LOG(ERROR) << "Could not lift function at " << std::hex << addr
                 << std::dec;
      return false;
    }
  }

  return true;
}

bool LiftCodeIntoModule(const remill::Arch *arch, const Program &program,
                        llvm::Module &module) {
  DLOG(INFO) << "LiftCodeIntoModule";
  FunctionLifter lifter(arch, program, module);
  // Forward declare all lifted functions
  program.ForEachFunction([&](const FunctionDecl *decl) {
    auto func = lifter.GetOrDeclareFunction(decl->address);
    // Set function as external so it doesn't get optimized away
    func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    return true;
  });

  if (!lifter.DefineLiftedFunctions()) {
    return false;
  }

  return true;
}

}  // namespace anvill
