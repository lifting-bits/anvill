#pragma once

#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Value.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Lifter.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "CodeLifter.h"
#include "anvill/Declarations.h"

namespace anvill {

enum : size_t {
  kNextPCArgNum = remill::kNumBlockArgs,
  kShouldReturnArgNum,
  kNumLiftedBasicBlockArgs
};

struct BasicBlockFunction {
  llvm::Function *func;
  llvm::Argument *pc_arg;
  llvm::Argument *mem_ptr;
  llvm::AllocaInst *next_pc_out;
  llvm::Argument *stack;
};

class CallableBasicBlockFunction;

/**
 * @brief A BasicBlockLifter lifts a basic block as a native function that takes 
 * in scope variables and returns in scope variables (essentially an SSAed form of the entire block)
 * In addition to variables a basic block also returns the successor of this block (if it exists, ie. function returns are terminating tail calls) to the caller given the input state. 
 */
class BasicBlockLifter : public CodeLifter {
 private:
  std::unique_ptr<BasicBlockContext> block_context;
  CodeBlock block_def;

  llvm::StructType *var_struct_ty{nullptr};

  // The allocated state ptr for the function.
  llvm::Value *state_ptr{nullptr};

  llvm::Function *lifted_func{nullptr};

  const FunctionDecl &decl;

  llvm::Function *bb_func{nullptr};

  FunctionLifter &flifter;

  llvm::BasicBlock *invalid_successor_block{nullptr};

  llvm::Function *DeclareBasicBlockFunction();

  llvm::StructType *StructTypeFromVars() const;

  remill::DecodingContext ApplyContextAssignments(
      const std::unordered_map<std::string, uint64_t> &assignments,
      remill::DecodingContext prev_context);

  remill::DecodingContext CreateDecodingContext(const CodeBlock &blk);


  void ApplyTypeHint(llvm::IRBuilder<> &bldr, const ValueDecl &type_hint);

  void LiftInstructionsIntoLiftedFunction();

  BasicBlockFunction CreateBasicBlockFunction();

  void TerminateBasicBlockFunction(llvm::Function *caller,
                                   llvm::IRBuilder<> &ir, llvm::Value *next_mem,
                                   llvm::Value *should_return,
                                   const BasicBlockFunction &bbfunc);

  bool ApplyInterProceduralControlFlowOverride(const remill::Instruction &insn,
                                               llvm::BasicBlock *&block);

  bool
  DoInterProceduralControlFlow(const remill::Instruction &insn,
                               llvm::BasicBlock *block,
                               const anvill::ControlFlowOverride &override);

  llvm::CallInst *AddCallFromBasicBlockFunctionToLifted(
      llvm::BasicBlock *source_block, llvm::Function *dest_func,
      const remill::IntrinsicTable &intrinsics,
      llvm::Value *next_pc_hint = nullptr);

  std::pair<uint64_t, llvm::Value *>
  LoadFunctionReturnAddress(const remill::Instruction &inst,
                            llvm::BasicBlock *block);

  bool DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                             remill::Instruction *inst_out,
                             remill::DecodingContext context);


  llvm::MDNode *GetBasicBlockAnnotation(uint64_t addr) const;

 public:
  BasicBlockLifter(std::unique_ptr<BasicBlockContext> block_context,
                   const FunctionDecl &decl, CodeBlock block_def,
                   const LifterOptions &options_,
                   llvm::Module *semantics_module,
                   const TypeTranslator &type_specifier,
                   FunctionLifter &flifter);


  void LiftBasicBlockFunction();


  using PointerProvider =
      std::function<llvm::Value *(const ParameterDecl &param)>;


  // Packs in scope variables into a struct
  void PackLiveValues(llvm::IRBuilder<> &bldr, llvm::Value *from_state_ptr,
                      PointerProvider into_vars,
                      const std::vector<BasicBlockVariable> &decls) const;

  void UnpackLiveValues(llvm::IRBuilder<> &, PointerProvider returned_value,
                        llvm::Value *into_state_ptr,
                        const std::vector<BasicBlockVariable> &) const;


  // Calls a basic block function and unpacks the result into the state
  llvm::CallInst *CallBasicBlockFunction(llvm::IRBuilder<> &,
                                         llvm::Value *state_ptr,
                                         llvm::Value *parent_stack,
                                         llvm::Value *memory_pointer) const;

  llvm::CallInst *ControlFlowCallBasicBlockFunction(
      llvm::Function *caller, llvm::IRBuilder<> &, llvm::Value *state_ptr,
      llvm::Value *parent_stack, llvm::Value *memory_pointer) const;

  BasicBlockLifter(BasicBlockLifter &&) = default;
};

class CallableBasicBlockFunction {

 private:
  llvm::Function *func;
  CodeBlock block;
  BasicBlockLifter bb_lifter;


 public:
  CallableBasicBlockFunction(llvm::Function *func, CodeBlock block,
                             BasicBlockLifter bb_lifter);

  llvm::Function *GetFunction() const;

  llvm::StructType *GetRetType() const;

  const CodeBlock &GetBlock() const;

  // Calls a basic block function and unpacks the result into the state
  void CallBasicBlockFunction(llvm::IRBuilder<> &, llvm::Value *state_ptr,
                              llvm::Value *stack_ptr) const;
};


}  // namespace anvill