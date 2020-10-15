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

#pragma once

#include <remill/Arch/Instruction.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>

#include <set>
#include <unordered_map>

namespace llvm {
class BasicBlock;
class Function;
class Module;
class LLVMContext;
}  // namespace llvm

namespace remill {
class Arch;
}  // namespace remill

namespace anvill {

class Program;
struct FunctionDecl;

struct FunctionEntry {
  // Lifted functions contain the remill semantics for the instructions
  // inside of a binary function.
  llvm::Function *lifted;

  // Wrapper function that converts lifted state, as represented by the
  // Remill `State` structure, to "native" or high-level state, as
  // represented by logical function arguments and return values.
  //
  // Before optimization, `lifted` functions call `lifted_to_native`
  // functions.
  llvm::Function *lifted_to_native;

  // Wrapper function that converts "native" or high-level state, as
  // represented by logical function arguments and return values, into
  // lifted state, as represented by the Remill `State` structure.
  //
  // Before optimization, the `native_to_lifted` calls the `lifted` function.
  llvm::Function *native_to_lifted;
};

class MCToIRLifter {
 private:
  const remill::Arch *arch;
  const Program &program;
  llvm::Module &module;
  llvm::LLVMContext &ctx;
  llvm::Function *lifted_func{nullptr};
  remill::Instruction *curr_inst{nullptr};
  remill::IntrinsicTable intrinsics;
  remill::InstructionLifter inst_lifter;

  // A work list of instructions to lift. The first entry in the work list
  // is the instruction PC; the second entry is the PC of how we got to even
  // ask about the first entry (provenance).
  std::set<std::pair<uint64_t, uint64_t>> work_list;

  // Result maps
  std::unordered_map<uint64_t, llvm::BasicBlock *> addr_to_block;

  // Maps program counters to function entries.
  std::unordered_map<uint64_t, FunctionEntry> addr_to_func;

  // Declare the function decl `decl` and return an `llvm::Function *`. The
  // returned function is a "high-level" function.
  FunctionEntry GetOrDeclareFunction(const FunctionDecl &decl);

  // Helper
  llvm::BasicBlock *GetOrCreateBlock(const uint64_t addr);

  // Visitors used to add terminators to instruction basic blocks
  void VisitInvalid(const remill::Instruction &inst,
                    llvm::BasicBlock *block);
  void VisitError(const remill::Instruction &inst,
                  remill::Instruction *delayed_inst,
                  llvm::BasicBlock *block);
  void VisitNormal(const remill::Instruction &inst,
                   llvm::BasicBlock *block);
  void VisitNoOp(const remill::Instruction &inst,
                 llvm::BasicBlock *block);
  void VisitDirectJump(const remill::Instruction &inst,
                       remill::Instruction *delayed_inst,
                       llvm::BasicBlock *block);
  void VisitIndirectJump(const remill::Instruction &inst,
                         remill::Instruction *delayed_inst,
                         llvm::BasicBlock *block);
  void VisitFunctionReturn(const remill::Instruction &inst,
                           remill::Instruction *delayed_inst,
                           llvm::BasicBlock *block);
  void VisitDirectFunctionCall(const remill::Instruction &inst,
                               remill::Instruction *delayed_inst,
                               llvm::BasicBlock *block);
  void VisitIndirectFunctionCall(const remill::Instruction &inst,
                                 remill::Instruction *delayed_inst,
                                 llvm::BasicBlock *block);
  void VisitConditionalBranch(const remill::Instruction &inst,
                              remill::Instruction *delayed_inst,
                              llvm::BasicBlock *block);
  void VisitAsyncHyperCall(const remill::Instruction &inst,
                           remill::Instruction *delayed_inst,
                           llvm::BasicBlock *block);
  void VisitConditionalAsyncHyperCall(const remill::Instruction &inst,
                                      remill::Instruction *delayed_inst,
                                      llvm::BasicBlock *block);

  void VisitDelayedInstruction(const remill::Instruction &inst,
                               remill::Instruction *delayed_inst,
                               llvm::BasicBlock *block,
                               bool on_taken_path);

  void VisitInstruction(remill::Instruction &inst, llvm::BasicBlock *block);

  bool DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                             remill::Instruction *inst_out);

 public:
  MCToIRLifter(const remill::Arch *arch, const Program &program,
               llvm::Module &module);


  // Lift the function decl `decl` and return an `FunctionEntry`.
  FunctionEntry LiftFunction(const FunctionDecl &decl);
};

}  // namespace anvill
