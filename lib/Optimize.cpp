/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "anvill/Optimize.h"

#include <glog/logging.h>

// clang-format off
#include <remill/BC/Compat/ScalarTransforms.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Transforms/IPO/Inliner.h>
#include <llvm/Transforms/IPO/GlobalDCE.h>
#include <llvm/Transforms/IPO/StripSymbols.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/Sink.h>
#include <llvm/Transforms/Scalar/NewGVN.h>
#include <llvm/Transforms/Scalar/SCCP.h>
#include <llvm/Transforms/Scalar/DeadStoreElimination.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/BDCE.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO/GlobalOpt.h>

#include <anvill/Providers.h>
#include <anvill/Passes/JumpTableAnalysis.h>
#include <anvill/Passes/CodeQualityStatCollector.h>
#include <anvill/Passes/BranchAnalysis.h>
#include <anvill/Passes/JumpTableAnalysis.h>
// clang-format on

#include <anvill/ABI.h>
#include <anvill/CrossReferenceResolver.h>
#include <anvill/Lifters.h>
#include <anvill/Passes/JumpTableAnalysis.h>
#include <anvill/Providers.h>
#include <anvill/Decls.h>
#include <anvill/Transforms.h>
#include <anvill/Utils.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>

#include <unordered_set>
#include <vector>

namespace anvill {

//// TODO(pag): NewGVN passes in debug build of LLVM on challenge 5.
//// NOTE(pag): Might also require the inliner to be present.
//
//class OurGVNPass : public llvm::PassInfoMixin<OurGVNPass> {
//public:
//  llvm::NewGVNPass pass;
//  /// Run the pass over the function.
//  llvm::PreservedAnalyses run(llvm::Function &F, llvm::AnalysisManager<llvm::Function> &AM) {
//    LOG(ERROR) << F.getName().str();
//    remill::StoreModuleToFile(F.getParent(), "/tmp/lifted.bc", true);
//    return pass.run(F, AM);
//  }
//};

class OurVerifierPass : public llvm::PassInfoMixin<OurVerifierPass> {
  llvm::VerifierPass pass;
  const unsigned line;
 public:
  inline explicit OurVerifierPass(unsigned line_)
      : line(line_) {}

  llvm::PreservedAnalyses run(llvm::Function &F, llvm::AnalysisManager<llvm::Function> &AM) {
    LOG(ERROR) << "Verifier at " << line;
    return pass.run(F, AM);
  }
};

// Optimize a module. This can be a module with semantics code, lifted
// code, etc.
// When utilizing crossRegisterProxies cleanup triggers asan

void OptimizeModule(const EntityLifter &lifter,
                    llvm::Module &module) {

  const LifterOptions &options = lifter.Options();
  const MemoryProvider &mp = lifter.MemoryProvider();
  SliceManager slc(lifter);
  EntityCrossReferenceResolver xr(lifter);

  if (auto err = module.materializeAll(); remill::IsError(err)) {
    LOG(FATAL) << remill::GetErrorString(err);
  }

  if (auto used = module.getGlobalVariable("llvm.used"); used) {
    used->setLinkage(llvm::GlobalValue::PrivateLinkage);
    used->eraseFromParent();
  }

  LOG(INFO) << "Optimizing module.";

  if (auto memory_escape = module.getFunction(kMemoryPointerEscapeFunction)) {
    for (auto call : remill::CallersOf(memory_escape)) {
      call->eraseFromParent();
    }
    memory_escape->eraseFromParent();
  }

  CHECK(remill::VerifyModule(&module));

  llvm::PassBuilder pb;
  llvm::ModulePassManager mpm(false);
  llvm::ModuleAnalysisManager mam(false);
  llvm::LoopAnalysisManager lam(false);
  llvm::CGSCCAnalysisManager cam(false);
//  llvm::InlineParams params;
  llvm::FunctionAnalysisManager fam(false);

  pb.registerFunctionAnalyses(fam);
  pb.registerModuleAnalyses(mam);
  pb.registerCGSCCAnalyses(cam);
  pb.registerLoopAnalyses(lam);

  fam.registerPass([&] { return JumpTableAnalysis(slc); });
  fam.registerPass([&] { return BranchAnalysis(); });

//  params.DefaultThreshold = 250;
//  auto inliner = llvm::ModuleInlinerWrapperPass(params);
//  mpm.addPass(std::move(inliner));

  mpm.addPass(llvm::GlobalOptPass());
  mpm.addPass(llvm::GlobalDCEPass());
  mpm.addPass(llvm::StripDeadDebugInfoPass());

  llvm::FunctionPassManager fpm;

  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::SinkingPass());

  // NewGVN has bugs with `____strtold_l_internal` from chal5, amd64.
//  fpm.addPass(llvm::NewGVNPass());

  fpm.addPass(llvm::SCCPPass());
  fpm.addPass(llvm::DSEPass());
  fpm.addPass(llvm::SROA());
  fpm.addPass(llvm::EarlyCSEPass(true));
  fpm.addPass(llvm::BDCEPass());
  fpm.addPass(llvm::SimplifyCFGPass());
  fpm.addPass(llvm::SinkingPass());
  fpm.addPass(llvm::SimplifyCFGPass());
  fpm.addPass(llvm::InstCombinePass());

  AddSinkSelectionsIntoBranchTargets(fpm);
  AddRemoveUnusedFPClassificationCalls(fpm);
  AddRemoveDelaySlotIntrinsics(fpm);
  AddRemoveErrorIntrinsics(fpm);
  AddLowerRemillMemoryAccessIntrinsics(fpm);
  AddRemoveCompilerBarriers(fpm);
  AddLowerTypeHintIntrinsics(fpm);
  AddHoistUsersOfSelectsAndPhis(fpm);
  fpm.addPass(llvm::InstCombinePass());
  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::SROA());

  // Sometimes we observe patterns where PC- and SP-related offsets are
  // accidentally truncated, and thus displacement-based analyses make them
  // look like really big 32-bit values, when really they are small negative
  // numbers that have been truncated and should have always been small 64-bit
  // negative numbers. Thus, we want to fixup such cases prior to any kind of
  // stack analysis.
  AddConvertMasksToCasts(fpm);

  AddLowerSwitchIntrinsics(fpm, slc, mp);
  AddSinkSelectionsIntoBranchTargets(fpm);
  AddRemoveTrivialPhisAndSelects(fpm);

  fpm.addPass(llvm::DCEPass());
  AddRemoveStackPointerCExprs(fpm, options.stack_frame_recovery_options);
  AddRecoverBasicStackFrame(fpm, options.stack_frame_recovery_options);
  fpm.addPass(llvm::SROA());
  AddSplitStackFrameAtReturnAddress(fpm, options.stack_frame_recovery_options);
  fpm.addPass(llvm::SROA());

  // Sometimes we have a values in the form of (expr ^ 1) used as branch
  // conditions or other targets. Try to fix these to be CMPs, since it
  // makes code easier to read and analyze. This is a fairly narrow optimization
  // but it comes up often enough for lifted code.
  AddConvertXorsToCmps(fpm);

  AddConvertIntegerToPointerOperations(fpm);
  AddConvertAddressesToEntityUses(fpm, xr);

  pb.crossRegisterProxies(lam, fam, cam, mam);

  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
  mpm.run(module, mam);

  llvm::FunctionPassManager second_fpm;

  AddTransformRemillJumpIntrinsics(second_fpm, xr);
  AddRemoveRemillFunctionReturns(second_fpm, xr);
  AddConvertSymbolicReturnAddressToConcreteReturnAddress(second_fpm);
  AddLowerRemillUndefinedIntrinsics(second_fpm);
  AddRemoveFailedBranchHints(second_fpm);
  second_fpm.addPass(llvm::NewGVNPass());
  AddSpreadPCMetadata(second_fpm, options);
  second_fpm.addPass(CodeQualityStatCollector());



  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(second_fpm)));
  mpm.run(module, mam);

  // Get rid of all final uses of `__anvill_pc`.
  if (auto anvill_pc = module.getGlobalVariable(::anvill::kSymbolicPCName)) {
    remill::ReplaceAllUsesOfConstant(
        anvill_pc, llvm::Constant::getNullValue(anvill_pc->getType()), &module);
  }

  // Manually clear the analyses to prevent ASAN failures in the destructors.
  mam.clear();
  fam.clear();
  cam.clear();
  lam.clear();

  CHECK(remill::VerifyModule(&module));
}

}  // namespace anvill
