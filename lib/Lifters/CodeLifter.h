#pragma once

#include <anvill/ABI.h>
#include <anvill/Type.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>

#include "anvill/Lifters.h"

namespace anvill {
/**
 * @brief A class that lifts machine level semantics to llvm
 * 
 */
class CodeLifter {
 protected:
  const LifterOptions &options;

  // Remill intrinsics inside of `module`.


  llvm::Module *semantics_module;

  remill::IntrinsicTable intrinsics;

  llvm::LLVMContext &llvm_context;

  remill::OperandLifter::OpLifterPtr op_lifter;


  // Are we lifting SPARC code? This affects whether or not we need to do
  // double checking on function return addresses;
  const bool is_sparc;

  // Are we lifting x86(-64) code?
  const bool is_x86_or_amd64;
  // Specification counter and stack pointer registers.
  const remill::Register *const pc_reg;
  const remill::Register *const sp_reg;


  const MemoryProvider &memory_provider;
  const TypeProvider &type_provider;
  const TypeTranslator &type_specifier;
  llvm::IntegerType *const address_type;


  // Convenient to keep around.
  llvm::Type *const i8_type;
  llvm::Constant *const i8_zero;
  llvm::Type *const i32_type;
  llvm::PointerType *const mem_ptr_type;
  llvm::PointerType *const state_ptr_type;

  llvm::Type *const pc_reg_type{nullptr};


  void RecursivelyInlineFunctionCallees(llvm::Function *inf);

  // Allocate and initialize the state structure.
  llvm::Value *AllocateAndInitializeStateStructure(llvm::BasicBlock *block,
                                                   const remill::Arch *arch);


  void
  InitializeStateStructureFromGlobalRegisterVariables(llvm::BasicBlock *block,
                                                      llvm::Value *state_ptr);

  void ArchSpecificStateStructureInitialization(llvm::BasicBlock *block,
                                                llvm::Value *new_state_ptr);

  unsigned pc_annotation_id;

  llvm::MDNode *GetAddrAnnotation(uint64_t addr,
                                  llvm::LLVMContext &context) const;

 public:
  CodeLifter(const LifterOptions &options, llvm::Module *semantics_module,
             const TypeTranslator &type_specifier);


  CodeLifter(CodeLifter &&) = default;
};

}  // namespace anvill