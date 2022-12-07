
#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <llvm/IR/Argument.h>
#include <remill/BC/Lifter.h>

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

  BasicBlockLifter(const BasicBlockContext &block_context,
                   const CodeBlock &block_def, const LifterOptions &options_);

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
  llvm::Function *LiftBasicBlockFunction();
};

}  // namespace anvill