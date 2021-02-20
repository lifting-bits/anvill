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

#pragma once

#include <cstdint>
#include <set>
#include <unordered_map>

#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>

#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>

namespace llvm {
class Function;
class LLVMContext;
class Module;
class Value;
}  // namespace llvm
namespace remill {
class Arch;
class Instruction;
class Register;
}  // namespace remill
namespace anvill {

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

// Orchestrates lifting of instructions and control-flow between instructions.
class FunctionLifter {
 public:
  FunctionLifter(const remill::Arch *arch_, MemoryProvider &memory_provider_,
                 TypeProvider &type_provider_, llvm::Module &semantics_module_);

  llvm::Function *LiftFunction(uint64_t address, llvm::FunctionType *func_type,
                               llvm::CallingConv::ID calling_convention);

 private:
  const remill::Arch * const arch;
  MemoryProvider &memory_provider;
  TypeProvider &type_provider;

  llvm::Module &module;
  llvm::LLVMContext &context;
  llvm::Function *lifted_func{nullptr};
  llvm::Value *state_ptr{nullptr};
  remill::Instruction *curr_inst{nullptr};
  remill::IntrinsicTable intrinsics;
  remill::InstructionLifter inst_lifter;

  llvm::Function *log_printf{nullptr};
  llvm::Value *log_format_str{nullptr};

  // A work list of instructions to lift. The first entry in the work list
  // is the instruction PC; the second entry is the PC of how we got to even
  // ask about the first entry (provenance).
  std::set<std::pair<uint64_t, uint64_t>> work_list;

  // Result maps
  std::unordered_map<uint64_t, llvm::BasicBlock *> addr_to_block;

  // Maps program counters to lifted functions.
  std::unordered_map<uint64_t, llvm::Function *> addr_to_func;

  // Declare the function decl `decl` and return an `llvm::Function *`. The
  // returned function is a "high-level" function.
  FunctionEntry GetOrDeclareFunction(
      uint64_t address, llvm::FunctionType *func_type,
      llvm::CallingConv::ID calling_convention);

  // Helper to get the basic block to contain the instruction at `addr`. This
  // function drives a work list, where the first time we ask for the
  // instruction at `addr`, we enqueue a bit of work to decode and lift that
  // instruction.
  llvm::BasicBlock *GetOrCreateBlock(const uint64_t addr);

  // The following `Visit*` methods exist to orchestrate control flow. The way
  // lifting works in Remill is that the mechanics of an instruction are
  // simulated by a single-entry, single-exit function, called a semantics
  // function. A `remill::Instruction` is basically a fancy package of
  // information describing what to pass to that function. However, many
  // instructions affect control-flow, and so that means that in order to
  // enact the control-flow changes that are implied by an instruction, we must
  // "orchestrate" lifting of control flow at a higher level, introduction
  // conditional branches and such between these called to semantics functions.

  // Visit an invalid instruction. An invalid instruction is a sequence of
  // bytes which cannot be decoded, or an empty byte sequence.
  void VisitInvalid(const remill::Instruction &inst, llvm::BasicBlock *block);

  // Visit an error instruction. An error instruction is guaranteed to trap
  // execution somehow, e.g. `ud2` on x86. Error instructions are treated
  // similarly to invalid instructions, with the exception that they can have
  // delay slots, and therefore the subsequent instruction may actually execute
  // prior to the error.
  void VisitError(const remill::Instruction &inst,
                  remill::Instruction *delayed_inst, llvm::BasicBlock *block);

  // Visit a normal instruction. Normal instructions have straight line control-
  // flow semantics, i.e. after executing the instruction, execution proceeds
  // to the next instruction (`inst.next_pc`).
  void VisitNormal(const remill::Instruction &inst, llvm::BasicBlock *block);

  // Visit a no-op instruction. These behave identically to normal instructions
  // from a control-flow perspective.
  void VisitNoOp(const remill::Instruction &inst, llvm::BasicBlock *block);

  // Visit a direct jump control-flow instruction. The target of the jump is
  // known at decode time, and the target address is available in
  // `inst.branch_taken_pc`. Execution thus needs to transfer to the instruction
  // (and thus `llvm::BasicBlock`) associated with `inst.branch_taken_pc`.
  void VisitDirectJump(const remill::Instruction &inst,
                       remill::Instruction *delayed_inst,
                       llvm::BasicBlock *block);

  // Visit an indirect jump control-flow instruction. This may be register- or
  // memory-indirect, e.g. `jmp rax` or `jmp [rax]` on x86. Thus, the target is
  // not know a priori and our default mechanism for handling this is to perform
  // a tail-call to the `__remill_jump` function, whose role is to be a stand-in
  // something that enacts the effect of "transfer to target."
  void VisitIndirectJump(const remill::Instruction &inst,
                         remill::Instruction *delayed_inst,
                         llvm::BasicBlock *block);

  // Visit a function return control-flow instruction, which is a form of
  // indirect control-flow, but with a certain semantic associated with
  // returning from a function. This is treated similarly to indirect jumps,
  // except the `__remill_function_return` function is tail-called.
  void VisitFunctionReturn(const remill::Instruction &inst,
                           remill::Instruction *delayed_inst,
                           llvm::BasicBlock *block);

  // Visit a direct function call control-flow instruction. The target is known
  // at decode time, and its realized address is stored in
  // `inst.branch_taken_pc`. In practice, what we do in this situation is try
  // to call the lifted function function at the target address.
  void VisitDirectFunctionCall(const remill::Instruction &inst,
                               remill::Instruction *delayed_inst,
                               llvm::BasicBlock *block);

  // Visit an indirect function call control-flow instruction. Similar to
  // indirect jumps, we invoke an intrinsic function, `__remill_function_call`;
  // however, unlike indirect jumps, we do not tail-call this intrinsic, and
  // we continue lifting at the instruction where execution will resume after
  // the callee returns. Thus, lifted bitcode maintains the call graph structure
  // as it presents itself in the binary.
  void VisitIndirectFunctionCall(const remill::Instruction &inst,
                                 remill::Instruction *delayed_inst,
                                 llvm::BasicBlock *block);

  // Helper to figure out the address where execution will resume after a
  // function call. In practice this is the instruction following the function
  // call, encoded in `inst.branch_not_taken_pc`. However, SPARC has a terrible
  // ABI where they inject an invalid instruction following some calls as a way
  // of communicating to the callee that they should return an object of a
  // particular, hard-coded size. Thus, we want to actually identify then ignore
  // that instruction, and present the following address for where execution
  // should resume after a `call`.
  std::pair<uint64_t, llvm::Value *>
  LoadFunctionReturnAddress(const remill::Instruction &inst,
                            llvm::BasicBlock *block);

  // Enact relevant control-flow changed after a function call. This figures
  // out the return address targeted by the callee and links it into the
  // control-flow graph.
  void VisitAfterFunctionCall(const remill::Instruction &inst,
                              llvm::BasicBlock *block);

  // Visit a conditional control-flow branch. Both the taken and not taken
  // targets are known by the decoder and their addresses are available in
  // `inst.branch_taken_pc` and `inst.branch_not_taken_pc`, respectively.
  // Here we need to orchestrate the two-way control-flow, as well as the
  // possible execution of a delayed instruction on either or both paths,
  // depending on the presence/absence of delay slot annulment bits.
  void VisitConditionalBranch(const remill::Instruction &inst,
                              remill::Instruction *delayed_inst,
                              llvm::BasicBlock *block);

  // Visit an asynchronous hyper call control-flow instruction. These are non-
  // local control-flow transfers, such as system calls. We treat them like
  // indirect function calls.
  void VisitAsyncHyperCall(const remill::Instruction &inst,
                           remill::Instruction *delayed_inst,
                           llvm::BasicBlock *block);

  // Visit conditional asynchronous hyper calls. These are conditional, non-
  // local control-flow transfers, e.g. `bound` on x86.
  void VisitConditionalAsyncHyperCall(const remill::Instruction &inst,
                                      remill::Instruction *delayed_inst,
                                      llvm::BasicBlock *block);

  // Visit (and thus lift) a delayed instruction. When lifting a delayed
  // instruction, we need to know if we're one the taken path of a control-flow
  // edge, or on the not-taken path. Delayed instructions appear physically
  // after some instructions, but execute logically before them in the
  // CPU pipeline. They are basically a way for hardware designers to push
  // the effort of keeping the pipeline full to compiler developers.
  void VisitDelayedInstruction(const remill::Instruction &inst,
                               remill::Instruction *delayed_inst,
                               llvm::BasicBlock *block, bool on_taken_path);

  // Instrument an instruction. This inject a `printf` call just before a
  // lifted instruction to aid in debugging.
  //
  // TODO(pag): In future, this mechanism should be used to provide a feedback
  //            loop, or to provide information to the `TypeProvider` for future
  //            re-lifting of code.
  //
  // TODO(pag): Right now, this feature is enabled by a command-line flag, and
  //            that flag is tested in `VisitInstruction`; we should move
  //            lifting configuration decisions out of here so that we can pass
  //            in a kind of `LiftingOptions` type that changes the lifter's
  //            behavior.
  void InstrumentInstruction(llvm::BasicBlock *block);

  // Visit an instruction, and lift it into a basic block. Then, based off of
  // the category of the instruction, invoke one of the category-specific
  // lifters to enact a change in control-flow.
  void VisitInstruction(
      remill::Instruction &inst, llvm::BasicBlock *block);

  llvm::Function *
  GetOrCreateTaintedFunction(llvm::Type *curr_type, llvm::Type *goal_type,
                             llvm::Module &mod, llvm::BasicBlock *curr_block,
                             const remill::Register *reg, uint64_t pc);

  // Try to decode an instruction at address `addr` into `*inst_out`. Returns
  // `true` is successful and `false` otherwise. `is_delayed` tells the decoder
  // whether or not the instruction being decoded is being decoded inside of a
  // delay slot of another instruction.
  bool DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                             remill::Instruction *inst_out);
};

}  // namespace anvill
