#include "CodeLifter.h"

#include <glog/logging.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Pass.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Context.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/Util.h>

#include <unordered_set>

namespace anvill {
namespace {
// Clear out LLVM variable names. They're usually not helpful.
static void ClearVariableNames(llvm::Function *func) {
  for (auto &block : *func) {
    //    block.setName(llvm::Twine::createNull());
    for (auto &inst : block) {
      if (inst.hasName()) {
        inst.setName(llvm::Twine::createNull());
      }
    }
  }
}
}  // namespace


void CodeLifter::RecursivelyInlineFunctionCallees(llvm::Function *inf) {
  std::vector<llvm::CallInst *> calls_to_inline;

  // Set of instructions that we should not annotate because we can't tie them
  // to a particular instruction address.
  std::unordered_set<llvm::Instruction *> insts_without_provenance;
  if (options.pc_metadata_name) {
    for (auto &inst : llvm::instructions(*inf)) {
      if (!inst.getMetadata(pc_annotation_id)) {
        insts_without_provenance.insert(&inst);
      }
    }
  }

  for (auto changed = true; changed; changed = !calls_to_inline.empty()) {
    calls_to_inline.clear();

    for (auto &inst : llvm::instructions(*inf)) {
      if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst); call_inst) {
        if (auto called_func = call_inst->getCalledFunction();
            called_func && !called_func->isDeclaration() &&
            !called_func->hasFnAttribute(llvm::Attribute::NoInline)) {
          calls_to_inline.push_back(call_inst);
        }
      }
    }

    for (llvm::CallInst *call_inst : calls_to_inline) {
      llvm::MDNode *call_pc = nullptr;
      if (options.pc_metadata_name) {
        call_pc = call_inst->getMetadata(pc_annotation_id);
      }

      llvm::InlineFunctionInfo info;
      auto res = llvm::InlineFunction(*call_inst, info);

      CHECK(res.isSuccess());

      // Propagate PC metadata from call sites into inlined call bodies.
      if (options.pc_metadata_name) {
        for (auto &inst : llvm::instructions(*inf)) {
          if (!inst.getMetadata(pc_annotation_id)) {
            if (insts_without_provenance.count(&inst)) {
              continue;

              // This call site had no associated PC metadata, and so we want
              // to exclude any inlined code from accidentally being associated
              // with other PCs on future passes.
            } else if (!call_pc) {
              insts_without_provenance.insert(&inst);

              // We can propagate the annotation.
            } else {
              inst.setMetadata(pc_annotation_id, call_pc);
            }
          }
        }
      }
    }
  }

  // Initialize cleanup optimizations


  if (llvm::verifyFunction(*inf, &llvm::errs())) {

    LOG(FATAL) << "Function verification failed: " << inf->getName().str()
               << " " << remill::LLVMThingToString(inf->getType());
  }

  llvm::legacy::FunctionPassManager fpm(inf->getParent());
  fpm.add(llvm::createCFGSimplificationPass());
  fpm.add(llvm::createPromoteMemoryToRegisterPass());
  fpm.add(llvm::createReassociatePass());
  fpm.add(llvm::createDeadStoreEliminationPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createSROAPass());
  fpm.add(llvm::createDeadCodeEliminationPass());
  fpm.add(llvm::createInstructionCombiningPass());
  fpm.doInitialization();
  fpm.run(*inf);
  fpm.doFinalization();

  ClearVariableNames(inf);
}
}  // namespace anvill