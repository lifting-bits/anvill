#pragma once

#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Value.h>
#include <remill/BC/Lifter.h>

#include <vector>

#include "CodeLifter.h"
#include "anvill/Declarations.h"

namespace anvill {


struct BasicBlockFunction {
  llvm::Function *func;
  llvm::Value *state_ptr;
  llvm::Argument *pc_arg;
  llvm::Argument *mem_ptr;
  llvm::Argument *next_pc_out_param;
};

class CallableBasicBlockFunction;

/**
 * @brief A BasicBlockLifter lifts a basic block as a native function that takes 
 * in scope variables and returns in scope variables (essentially an SSAed form of the entire block)
 * In addition to variables a basic block also returns the successor of this block (if it exists, ie. function returns are terminating tail calls) to the caller given the input state. 
 */
class BasicBlockLifter : public CodeLifter {
 private:
  const BasicBlockContext &block_context;
  const CodeBlock &block_def;

  // The allocated state ptr for the function.
  llvm::Value *state_ptr;

  remill::DecodingContext ApplyContextAssignments(
      const std::unordered_map<std::string, uint64_t> &assignments,
      remill::DecodingContext prev_context);

  remill::DecodingContext CreateDecodingContext(const CodeBlock &blk);

  void LiftBasicBlockIntoFunction(BasicBlockFunction &basic_block_function);

  BasicBlockFunction CreateBasicBlockFunction();

  bool ApplyInterProceduralControlFlowOverride(const remill::Instruction &insn,
                                               llvm::BasicBlock *&block);

  bool
  DoInterProceduralControlFlow(const remill::Instruction &insn,
                               llvm::BasicBlock *block,
                               const anvill::ControlFlowOverride &override);

  llvm::CallInst *AddCallFromBasicBlockFunctionToLifted(
      llvm::BasicBlock *source_block, llvm::Function *dest_func,
      const remill::IntrinsicTable &intrinsics);

  std::pair<uint64_t, llvm::Value *>
  LoadFunctionReturnAddress(const remill::Instruction &inst,
                            llvm::BasicBlock *block);

  bool DecodeInstructionInto(const uint64_t addr, bool is_delayed,
                             remill::Instruction *inst_out,
                             remill::DecodingContext context);


  llvm::MDNode *GetBasicBlockAnnotation(uint64_t addr) const;


 public:
  BasicBlockLifter(const BasicBlockContext &block_context,
                   const CodeBlock &block_def, const LifterOptions &options_,
                   llvm::Module *semantics_module,
                   const TypeTranslator &type_specifier);
  static CallableBasicBlockFunction
  LiftBasicBlock(const BasicBlockContext &block_context,
                 const CodeBlock &block_def, const LifterOptions &options_,
                 llvm::Module *semantics_module,
                 const TypeTranslator &type_specifier);


  CallableBasicBlockFunction LiftBasicBlockFunction() &&;

  // Packs in scope variables into a struct
  llvm::Value *PackLocals(llvm::IRBuilder<> &, llvm::Value *from_state_ptr,
                          const std::vector<ParameterDecl> &) const;

  void UnpackLocals(llvm::IRBuilder<> &, llvm::Value *returned_value,
                    llvm::Value *into_state_ptr,
                    const std::vector<ParameterDecl> &) const;


  // Calls a basic block function and unpacks the result into the state
  void CallBasicBlockFunction(llvm::IRBuilder<> &, llvm::Value *state_ptr,
                              const CallableBasicBlockFunction &) const;

  llvm::StructType *
  StructTypeFromVars(const std::vector<ParameterDecl> &in_scope_locals) const;

  BasicBlockLifter(BasicBlockLifter &&) = default;
};

class CallableBasicBlockFunction {

 private:
  llvm::Function *func;
  std::vector<ParameterDecl> in_scope_locals;
  CodeBlock block;
  BasicBlockLifter bb_lifter;


 public:
  CallableBasicBlockFunction(llvm::Function *func,
                             std::vector<ParameterDecl> in_scope_locals,
                             CodeBlock block, BasicBlockLifter bb_lifter);

  const std::vector<ParameterDecl> &GetInScopeVaraibles() const;
  llvm::Function *GetFunction() const;

  llvm::StructType *GetRetType() const;

  const CodeBlock &GetBlock() const;

  // Calls a basic block function and unpacks the result into the state
  void CallBasicBlockFunction(llvm::IRBuilder<> &,
                              llvm::Value *state_ptr) const;
};


}  // namespace anvill