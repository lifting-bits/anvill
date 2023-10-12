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
#include <anvill/Specification.h>
#include <anvill/Type.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/CallingConv.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <remill/Arch/Context.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <utility>

#include "CodeLifter.h"
#include "Lifters/BasicBlockLifter.h"

namespace std {
template <typename T1, typename T2>
struct hash<std::pair<T1, T2>> {
  std::size_t operator()(std::pair<T1, T2> const &p) const {
    std::size_t seed(0);
    llvm::hash_combine(seed, p.first);
    llvm::hash_combine(seed, p.second);

    return seed;
  }
};
}  // namespace std

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


struct LiftedFunction {
  llvm::Function *func;
  llvm::Argument *state_ptr;
  llvm::Argument *pc_arg;
  llvm::Argument *mem_ptr;
};


// Orchestrates lifting of instructions and control-flow between instructions.
class FunctionLifter : public CodeLifter {
  friend class BasicBlockLifter;

 public:
  ~FunctionLifter(void);


  static FunctionLifter CreateFunctionLifter(const LifterOptions &options_);

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
  llvm::Function *AddFunctionToContext(llvm::Function *func,
                                       const FunctionDecl &decl,
                                       EntityLifterImpl &lifter_context) const;

  // Get or create a basic block lifter for the basic block with specified
  // uid. If a lifter for the uid does not exist, this function will create it
  BasicBlockLifter &GetOrCreateBasicBlockLifter(Uid uid);

  const BasicBlockLifter &LiftBasicBlockFunction(const CodeBlock &);

  llvm::Function *GetBasicBlockFunction(uint64_t address) const;

 private:
  FunctionLifter(const LifterOptions &options_,
                 std::unique_ptr<llvm::Module> semantics_module);

  // Semantics module containing all instruction semantics.
  std::unique_ptr<llvm::Module> semantics_module;

  TypeTranslator type_specifier;


  llvm::MDNode *pc_annotation{nullptr};

  // Address of the function currently being lifted.
  uint64_t func_address{0};

  // The declaration of the current function being lifted.
  const FunctionDecl *curr_decl{nullptr};

  // The higher-level C/C++-like function that we're trying to lift.
  llvm::Function *native_func{nullptr};

  // Three-argument Remill function into which instructions are lifted.
  llvm::Function *lifted_func{nullptr};


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
  std::set<std::tuple<uint64_t, uint64_t>> edge_work_list;

  // We assume decoding contexts are constant per edge. If this is not the case a lot of things wont work out
  std::map<std::pair<uint64_t, uint64_t>, remill::DecodingContext>
      decoding_contexts;

  // Maps an instruction address to a basic block that will hold the lifted code
  // for that instruction.
  std::unordered_map<uint64_t, llvm::BasicBlock *> addr_to_block;

  // Maps program counters to lifted functions.
  std::unordered_map<uint64_t, llvm::Function *> addr_to_func;

  // maps a uid to the lifter for that block
  std::unordered_map<std::pair<uint64_t, uint64_t>, BasicBlockLifter>
      bb_lifters;

  // Get the annotation for the program counter `pc`, or `nullptr` if we're
  // not doing annotations.
  llvm::MDNode *GetPCAnnotation(uint64_t pc) const;

  // Declare the function decl `decl` and return an `llvm::Function *`. The
  // returned function is a "high-level" function.
  llvm::Function *GetOrDeclareFunction(const FunctionDecl &decl);

  void InsertError(llvm::BasicBlock *block);


  remill::DecodingContext
  ApplyTargetList(const std::unordered_map<std::string, uint64_t> &assignments,
                  remill::DecodingContext prev_context);


  void VisitConditionalInstruction(
      const remill::Instruction &inst,
      std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block,
      const remill::Instruction::ConditionalInstruction &conditional_insn,
      const remill::DecodingContext &prev_context);

  // Visit a function return control-flow instruction, which is a form of
  // indirect control-flow, but with a certain semantic associated with
  // returning from a function. This is treated similarly to indirect jumps,
  // except the `__remill_function_return` function is tail-called.
  void VisitFunctionReturn(const remill::Instruction &inst,
                           std::optional<remill::Instruction> &delayed_inst,
                           llvm::BasicBlock *block);


  // Try to resolve `target_pc` to a lifted function, and introduce
  // a function call to that address in `block`. Failing this, add a call
  // to `__remill_function_call`.
  // Returns true if the callee may return, false otherwise.
  bool CallFunction(const remill::Instruction &inst, llvm::BasicBlock *block,
                    std::optional<std::uint64_t> target_pc);

  // Visit a direct function call control-flow instruction. The target is known
  // at decode time, and its realized address is stored in
  // `inst.branch_taken_pc`. In practice, what we do in this situation is try
  // to call the lifted function function at the target address.
  void VisitDirectFunctionCall(const remill::Instruction &inst,
                               std::optional<remill::Instruction> &delayed_inst,
                               llvm::BasicBlock *block,
                               const remill::Instruction::DirectFunctionCall &,
                               const remill::DecodingContext &);


  // Visit an indirect function call control-flow instruction. Similar to
  // indirect jumps, we invoke an intrinsic function, `__remill_function_call`;
  // however, unlike indirect jumps, we do not tail-call this intrinsic, and
  // we continue lifting at the instruction where execution will resume after
  // the callee returns. Thus, lifted bitcode maintains the call graph structure
  // as it presents itself in the binary.
  void VisitIndirectFunctionCall(
      const remill::Instruction &inst,
      std::optional<remill::Instruction> &delayed_inst, llvm::BasicBlock *block,
      const remill::Instruction::IndirectFunctionCall &ind_call,
      const remill::DecodingContext &);


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
                            llvm::BasicBlock *block, llvm::Value *state_ptr);

  void VisitBlock(CodeBlock entry_context, llvm::Value *lifted_function_state,
                  llvm::Value *abstract_stack);

  LiftedFunction CreateLiftedFunction(const std::string &name);

  remill::DecodingContext CreateDecodingContext(const CodeBlock &blk);


  void VisitBlocks(llvm::Value *lifted_function_state,
                   llvm::Value *abstract_stack);

  // Try to decode an instruction at address `addr` into `*inst_out`. Returns
  // a context map if sueccessful and std::nullopt otherwise. `is_delayed` tells the decoder
  // whether or not the instruction being decoded is being decoded inside of a
  // delay slot of another instruction.
  bool DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                             remill::Instruction *inst_out,
                             remill::DecodingContext curr_context);

  // Set up `native_func` to be able to call `lifted_func`. This means
  // marshalling high-level argument types into lower-level values to pass into
  // a stack-allocated `State` structure. This also involves providing initial
  // default values for registers.
  void CallLiftedFunctionFromNativeFunction(const FunctionDecl &decl);

  // In practice, lifted functions are not workable as is; we need to emulate
  // `__attribute__((flatten))`, i.e. recursively inline as much as possible, so
  // that all semantics and helpers are completely inlined.
  void RecursivelyInlineLiftedFunctionIntoNativeFunction(void);

  // Manipulates the control flow to restore intra-procedural state when reaching an
  // inter-procedural effect.
  // Returns a boolean represnting wether decoding should continue (true = non-terminal, false=terminal)
  bool ApplyInterProceduralControlFlowOverride(const remill::Instruction &,
                                               llvm::BasicBlock *&block,
                                               llvm::Value *state_ptr);

  bool DoInterProceduralControlFlow(const remill::Instruction &insn,
                                    llvm::BasicBlock *block,
                                    const anvill::ControlFlowOverride &override,
                                    llvm::Value *state_ptr);

  // Perform architecture-specific initialization of the state structure
  // in `block`.
  void ArchSpecificStateStructureInitialization(llvm::BasicBlock *block,
                                                llvm::Value *state_ptr);

  // Initialize the state structure with default values, loaded from global
  // variables. The purpose of these global variables is to show that there are
  // some unmodelled external dependencies inside of a lifted function.
  void
  InitializeStateStructureFromGlobalRegisterVariables(llvm::BasicBlock *block,
                                                      llvm::Value *state_ptr);
};

}  // namespace anvill
