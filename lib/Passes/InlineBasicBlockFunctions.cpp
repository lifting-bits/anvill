#include "anvill/Passes/InlineBasicBlockFunctions.h"

#include <anvill/ABI.h>
#include <anvill/Passes/RemoveAssignmentsToNextPC.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/BC/Util.h>

#include <optional>

#include "Utils.h"

namespace anvill {

llvm::StringRef InlineBasicBlockFunctions::name(void) {
  return "Inline the basic block functions";
}

llvm::PreservedAnalyses InlineBasicBlockFunctions::runOnBasicBlockFunction(
    llvm::Function &F, llvm::FunctionAnalysisManager &AM,
    const anvill::BasicBlockContext &cont) {
  F.removeFnAttr(llvm::Attribute::NoInline);
  F.addFnAttr(llvm::Attribute::AlwaysInline);
  return llvm::PreservedAnalyses::all();
}

}  // namespace anvill