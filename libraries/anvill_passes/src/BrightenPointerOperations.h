#ifndef __POINTER_LIFTER
#define __POINTER_LIFTER

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instruction.h>
#include <llvm/Passes/PassBuilder.h>
#include <remill/BC/Util.h>
#include <string>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <anvill/Transforms.h>
#include <anvill/Analysis/CrossReferenceResolver.h>

namespace anvill {

class PointerLifter
    : public llvm::InstVisitor<PointerLifter, std::pair<llvm::Value *, bool>> {
 public:
  // this is my one requirement: I call a function, get a function pass. I can pass that function a cross-reference resolver instance, and when you get to an llvm::Constant, it will use the xref resolver on that
  PointerLifter(llvm::Module *mod, const CrossReferenceResolver &resolver) : module(mod), xref_resolver(resolver), changed(false) {}

  // ReplaceAllUses - swaps uses of LLVM inst with other LLVM inst
  // Adds users to the next worklist, for downstream type propagation
  void ReplaceAllUses(llvm::Value *orig_inst, llvm::Value *new_inst);

  // We need to get a pointer from some value
  llvm::Value *getPointerToValue(llvm::IRBuilder<> &ir, llvm::Value *curr_val,
                                 llvm::Type *dest_type);

  // These visitor methods indicate that we know about pointer information to propagate
  // Some are maybes, because not all cast instructions are casts to pointers.
  std::pair<llvm::Value *, bool> visitIntToPtrInst(llvm::IntToPtrInst &inst);
  std::pair<llvm::Value *, bool> visitLoadInst(llvm::LoadInst &inst);

  // std::pair<llvm::Value*, bool>visitPtrToIntInst(llvm::PtrToIntInst &inst);
  std::pair<llvm::Value *, bool>
  visitGetElementPtrInst(llvm::GetElementPtrInst &inst);
  std::pair<llvm::Value *, bool> visitBitCastInst(llvm::BitCastInst &inst);

  // std::pair<llvm::Value*, bool>visitCastInst(llvm::CastInst &inst);
  // Simple wrapper for storing the type information into the list, and then calling visit.
  std::pair<llvm::Value *, bool> visitInferInst(llvm::Instruction *inst,
                                                llvm::Type *inferred_type);
  std::pair<llvm::Value *, bool> visitInstruction(llvm::Instruction &I);
  std::pair<llvm::Value *, bool>
  visitBinaryOperator(llvm::BinaryOperator &inst);

  llvm::Value *GetIndexedPointer(llvm::IRBuilder<> &ir, llvm::Value *address,
                                 llvm::Value *offset, llvm::Type *t);

  // Driver method
  void LiftFunction(llvm::Function& func);

 private:
  std::unordered_map<llvm::Value *, llvm::Type *> inferred_types;
  std::vector<llvm::Instruction *> next_worklist;
  std::unordered_set<llvm::Instruction *> to_remove;
  std::unordered_map<llvm::Instruction *, llvm::Value *> rep_map;
  bool changed;
  llvm::Module *module;

  const CrossReferenceResolver & xref_resolver;
};

class PointerLifterPass : public llvm::FunctionPass {
  public:
      PointerLifterPass(const CrossReferenceResolver &resolver): xref_resolver(resolver), FunctionPass(ID) {}
      bool runOnFunction(llvm::Function &f);
  private:
      static char ID;
      const CrossReferenceResolver &xref_resolver;

      
};

};  // namespace anvill

#endif
