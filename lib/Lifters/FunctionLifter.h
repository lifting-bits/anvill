/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Type.h>
#include <llvm/IR/CallingConv.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>

namespace llvm {
class Constant;
class Function;
class FunctionType;
class LLVMContext;
class MDNode;
class Module;
class Value;
}  // namespace llvm
namespace remill {
class Arch;
class Instruction;
struct Register;
}  // namespace remill
namespace anvill {

class EntityLifterImpl;
class MemoryProvider;
class TypeProvider;
struct ControlFlowTargetList;

// Orchestrates lifting of instructions and control-flow between instructions.
class FunctionLifter {
 public:
  ~FunctionLifter(void);

  FunctionLifter(const LifterOptions &options_);

  // Declare a lifted a function. Will return `nullptr` if the memory is
  // not accessible or executable.
  llvm::Function *DeclareFunction(const FunctionDecl &decl);

  // Lift a function. Will return `nullptr` if the memory is
  // not accessible or executable.
  llvm::Function *LiftFunction(const FunctionDecl &decl);

  // Returns the address of a named function.
  std::optional<uint64_t>
  AddressOfNamedFunction(const std::string &func_name) const;

  // Update the associated entity lifter with information about this
  // function, and copy the function into the context's module. Returns the
  // version of `func` inside the module of the lifter context.
  llvm::Function *AddFunctionToContext(llvm::Function *func, uint64_t address,
                                       EntityLifterImpl &lifter_context) const;

 private:
  const LifterOptions &options;
  const MemoryProvider &memory_provider;
  const TypeProvider &type_provider;
  const TypeTranslator type_specifier;

  // Semantics module containing all instruction semantics.
  std::unique_ptr<llvm::Module> semantics_module;

  // Context associated with `module`.
  llvm::LLVMContext &llvm_context;

  // Remill intrinsics inside of `module`.
  remill::IntrinsicTable intrinsics;

  // TODO(pag): Consider passing in the `InstructionLifter` via `LifterOptions`?
  remill::InstructionLifter inst_lifter;

  // Specification counter and stack pointer registers.
  const remill::Register * const pc_reg;
  const remill::Register * const sp_reg;

  // Are we lifting SPARC code? This affects whether or not we need to do
  // double checking on function return addresses;
  const bool is_sparc;

  // Are we lifting x86(-64) code?
  const bool is_x86_or_amd64;

  // Convenient to keep around.
  llvm::Type *const i8_type;
  llvm::Constant *const i8_zero;
  llvm::Type *const i32_type;
  llvm::PointerType *const mem_ptr_type;
  llvm::PointerType *const state_ptr_type;
  llvm::IntegerType *const address_type;
  llvm::Type *const pc_reg_type{nullptr};

  // Metadata node to attach to lifted instructions to related them to
  // original instructions.
  unsigned pc_annotation_id{0};

  llvm::MDNode *pc_annotation{nullptr};

  // Address of the function currently being lifted.
  uint64_t func_address{0};

  // The declaration of the current function being lifted.
  const FunctionDecl *curr_decl{nullptr};

  // The higher-level C/C++-like function that we're trying to lift.
  llvm::Function *native_func{nullptr};

  // Three-argument Remill function into which instructions are lifted.
  llvm::Function *lifted_func{nullptr};

  // State pointer in `lifted_func`.
  llvm::Value *state_ptr{nullptr};

  // Pointer to the `Memory *` in `lifted_func`.
  llvm::Value *mem_ptr_ref{nullptr};

  // Pointer to the current value of the stack pointer in `lifted_func`.
  llvm::Value *sp_reg_ref{nullptr};

  // Pointer to the current value of the program counter in `lifted_func`.
  llvm::Value *pc_reg_ref{nullptr};

  // Pointer to the next value of the program counter in `lifted_func`.
  llvm::Value *next_pc_reg_ref{nullptr};

  // Current instruction being lifted.
  remill::Instruction *curr_inst{nullptr};

  // The function that we use to track data provenance. This is a variadic
  // function that takes each register as an argument. The parameters are
  // untyped, due to using a variadic argument list.
  //
  // TODO(pag): Think about eventually having one per architecture.
  llvm::Function *data_provenance_function{nullptr};

  // Mapping of function names to addresses.
  std::unordered_map<std::string, uint64_t> func_name_to_address;

  // A work list of instructions to lift. The first entry in the work list
  // is the instruction PC; the second entry is the PC of how we got to even
  // ask about the first entry (provenance).
  //
  // NOTE(pag): The destination PC of the edge comes first in the work list so
  //            that the ordering of the `std::set` processes the instructions
  //            roughly in order.
  std::set<std::pair<uint64_t, uint64_t>> edge_work_list;

  // Maps control flow edges `(from_pc -> to_pc)` to the basic block associated
  // with `to_pc`.
  std::map<std::pair<uint64_t, uint64_t>, llvm::BasicBlock *>
      edge_to_dest_block;

  // Maps an instruction address to a basic block that will hold the lifted code
  // for that instruction.
  std::unordered_map<uint64_t, llvm::BasicBlock *> addr_to_block;

  // Maps program counters to lifted functions.
  std::unordered_map<uint64_t, llvm::Function *> addr_to_func;

  // Get the annotation for the program counter `pc`, or `nullptr` if we're
  // not doing annotations.
  llvm::MDNode *GetPCAnnotation(uint64_t pc) const;

  // Declare the function decl `decl` and return an `llvm::Function *`. The
  // returned function is a "high-level" function.
  llvm::Function *GetOrDeclareFunction(const FunctionDecl &decl);

  // Helper to get the basic block to contain the instruction at `addr`. This
  // function drives a work list, where the first time we ask for the
  // instruction at `addr`, we enqueue a bit of work to decode and lift that
  // instruction.
  llvm::BasicBlock *GetOrCreateBlock(uint64_t from_addr, uint64_t to_addr);

  // Attempts to lookup any redirection of the given address, and then
  // calls GetOrCreateBlock
  llvm::BasicBlock *GetOrCreateTargetBlock(const remill::Instruction &from_inst,
                                           uint64_t to_addr);

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

  // Visit an indirect jump that is a jump table.
  void DoSwitchBasedIndirectJump(const remill::Instruction &inst,
                                 llvm::BasicBlock *block,
                                 const ControlFlowTargetList &target_list);

  // Visit a conditional indirect jump control-flow instruction. This is a mix
  // between indirect jumps and conditional jumps that appears on the
  // ARMv7 (AArch32) architecture, where many instructions are predicated.
  void VisitConditionalIndirectJump(const remill::Instruction &inst,
                                    remill::Instruction *delayed_inst,
                                    llvm::BasicBlock *block);

  // Visit a function return control-flow instruction, which is a form of
  // indirect control-flow, but with a certain semantic associated with
  // returning from a function. This is treated similarly to indirect jumps,
  // except the `__remill_function_return` function is tail-called.
  void VisitFunctionReturn(const remill::Instruction &inst,
                           remill::Instruction *delayed_inst,
                           llvm::BasicBlock *block);

  // Visit a conditional function return control-flow instruction, which is a
  // variant that is half-way between a return and a conditional jump. These
  // are possible on ARMv7 (AArch32).
  void VisitConditionalFunctionReturn(const remill::Instruction &inst,
                                      remill::Instruction *delayed_inst,
                                      llvm::BasicBlock *block);

  // Call `pc` in `block`, treating it as a callable declaration `decl`.
  // Returns the new value of the memory pointer (after it is stored to
  // `MEMORY`).
  llvm::Value *CallCallableDecl(
      llvm::BasicBlock *block, llvm::Value *pc, CallableDecl decl);

  // Try to resolve `target_pc` to a lifted function, and introduce
  // a function call to that address in `block`. Failing this, add a call
  // to `__remill_function_call`.
  void CallFunction(const remill::Instruction &inst, llvm::BasicBlock *block,
                    std::optional<std::uint64_t> target_pc);

  // A wrapper around the type provider's TryGetFunctionType that makes use
  // of the control flow provider to handle control flow redirections for
  // thunks
  std::optional<CallableDecl> TryGetTargetFunctionType(
      const remill::Instruction &inst, std::uint64_t address,
      std::uint64_t redirected_address);

  // Visit a direct function call control-flow instruction. The target is known
  // at decode time, and its realized address is stored in
  // `inst.branch_taken_pc`. In practice, what we do in this situation is try
  // to call the lifted function function at the target address.
  void VisitDirectFunctionCall(const remill::Instruction &inst,
                               remill::Instruction *delayed_inst,
                               llvm::BasicBlock *block);

  // Visit a conditional direct function call control-flow instruction. The
  // target is known at decode time, and its realized address is stored in
  // `inst.branch_taken_pc`. In practice, what we do in this situation is try
  // to call the lifted function function at the target address if the condition
  // is satisfied. Note that it is up to the semantics of the conditional call
  // instruction to "tell us" if the condition is met.
  void VisitConditionalDirectFunctionCall(const remill::Instruction &inst,
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


  // Visit a conditional indirect function call control-flow instruction.
  // This is a cross between conditional jumps and indirect function calls.
  void VisitConditionalIndirectFunctionCall(const remill::Instruction &inst,
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
  void InstrumentDataflowProvenance(llvm::BasicBlock *block);

  // Adds a 'breakpoint' instrumentation, which calls functions that are named
  // with an instruction's address just before that instruction executes. These
  // are nifty to spot checking bitcode.
  void InstrumentCallBreakpointFunction(llvm::BasicBlock *block);

  // Visit an instruction, and lift it into a basic block. Then, based off of
  // the category of the instruction, invoke one of the category-specific
  // lifters to enact a change in control-flow.
  void VisitInstruction(remill::Instruction &inst, llvm::BasicBlock *block);

  // In the process of lifting code, we may want to call another native
  // function, `native_func`, for which we have high-level type info. The main
  // lifter operates on a special three-argument form function style, and
  // operating on this style is actually to our benefit, as it means that as
  // long as we can put data into the emulated `State` structure and pull it
  // out, then calling one native function from another doesn't require /us/
  // to know how to adapt one native return type into another native return
  // type, and instead we let LLVM's optimizations figure it out later during
  // scalar replacement of aggregates (SROA).
  llvm::Value *TryCallNativeFunction(FunctionDecl decl,
                                     llvm::Function *native_func,
                                     llvm::BasicBlock *block);

  // Visit all instructions. This runs the work list and lifts instructions.
  void VisitInstructions(uint64_t address);

  // Try to decode an instruction at address `addr` into `*inst_out`. Returns
  // `true` is successful and `false` otherwise. `is_delayed` tells the decoder
  // whether or not the instruction being decoded is being decoded inside of a
  // delay slot of another instruction.
  bool DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                             remill::Instruction *inst_out);

  // Set up `native_func` to be able to call `lifted_func`. This means
  // marshalling high-level argument types into lower-level values to pass into
  // a stack-allocated `State` structure. This also involves providing initial
  // default values for registers.
  void CallLiftedFunctionFromNativeFunction(const FunctionDecl &decl);

  // In practice, lifted functions are not workable as is; we need to emulate
  // `__attribute__((flatten))`, i.e. recursively inline as much as possible, so
  // that all semantics and helpers are completely inlined.
  void RecursivelyInlineLiftedFunctionIntoNativeFunction(void);

  // Allocate and initialize the state structure.
  void AllocateAndInitializeStateStructure(llvm::BasicBlock *block);

  // Perform architecture-specific initialization of the state structure
  // in `block`.
  void ArchSpecificStateStructureInitialization(llvm::BasicBlock *block);

  // Initialize the state structure with default values, loaded from global
  // variables. The purpose of these global variables is to show that there are
  // some unmodelled external dependencies inside of a lifted function.
  void
  InitializeStateStructureFromGlobalRegisterVariables(llvm::BasicBlock *block);
};

}  // namespace anvill
