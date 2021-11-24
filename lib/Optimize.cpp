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
#include <remill/BC/Compat/CTypes.h>
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

#include <anvill/Providers.h>
#include <anvill/Transforms.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>

#include <unordered_set>
#include <vector>

#include "anvill/ABI.h"
#include "anvill/Specification.h"
#include "anvill/Lifter.h"
#include "anvill/Utils.h"

DEFINE_uint32(
    pointer_brighten_gas, 64u,
    "Amount of internal iterations permitted for the pointer brightening pass.");

namespace anvill {

// Optimize a module. This can be a module with semantics code, lifted
// code, etc.
// When utilizing crossRegisterProxies cleanup triggers asan

void OptimizeModule(const EntityLifter &lifter_context,
                    llvm::Module &module) {

  const LifterOptions &options = lifter_context.Options();
  const remill::Arch *arch = options.arch;
  const MemoryProvider &mem_provider = lifter_context.MemoryProvider();

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


  llvm::PassBuilder pb;
  llvm::ModulePassManager mpm(false);
  llvm::ModuleAnalysisManager mam(false);
  llvm::LoopAnalysisManager lam(false);
  llvm::CGSCCAnalysisManager cam(false);
  llvm::InlineParams params;
  llvm::FunctionAnalysisManager fam(false);
  SliceManager slc(lifter_context);

  pb.registerFunctionAnalyses(fam);
  pb.registerModuleAnalyses(mam);
  pb.registerCGSCCAnalyses(cam);
  pb.registerLoopAnalyses(lam);

  fam.registerPass([&] { return JumpTableAnalysis(slc); });
  fam.registerPass([&] { return BranchAnalysis(); });

  params.DefaultThreshold = 250;
  auto inliner = llvm::ModuleInlinerWrapperPass(params);
  mpm.addPass(std::move(inliner));
  mpm.addPass(llvm::GlobalOptPass());
  mpm.addPass(llvm::GlobalDCEPass());
  mpm.addPass(llvm::StripDeadDebugInfoPass());


  llvm::FunctionPassManager fpm;

  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::SinkingPass());
  fpm.addPass(llvm::NewGVNPass());
  fpm.addPass(llvm::SCCPPass());
  fpm.addPass(llvm::DSEPass());
  fpm.addPass(llvm::SROA());
  fpm.addPass(llvm::EarlyCSEPass(true));
  fpm.addPass(llvm::BDCEPass());
  fpm.addPass(llvm::SimplifyCFGPass());
  fpm.addPass(llvm::SinkingPass());
  fpm.addPass(llvm::SimplifyCFGPass());
  fpm.addPass(llvm::InstCombinePass());

  auto error_manager_ptr = ITransformationErrorManager::Create();
  auto &err_man = *error_manager_ptr.get();

  AddSinkSelectionsIntoBranchTargets(fpm);
  AddRemoveUnusedFPClassificationCalls(fpm);
  AddRemoveDelaySlotIntrinsics(fpm);
  AddRemoveErrorIntrinsics(fpm);
  AddLowerRemillMemoryAccessIntrinsics(fpm);
  AddRemoveCompilerBarriers(fpm);
  AddLowerTypeHintIntrinsics(fpm);
  AddInstructionFolderPass(fpm, err_man);
  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::SROA());

  // Sometimes we observe patterns where PC- and SP-related offsets are
  // accidentally truncated, and thus displacement-based analyses make them
  // look like really big 32-bit values, when really they are small negative
  // numbers that have been truncated and should have always been small 64-bit
  // negative numbers. Thus, we want to fixup such cases prior to any kind of
  // stack analysis.
  AddConvertMasksToCasts(fpm);

  AddLowerSwitchIntrinsics(fpm, slc, mem_provider);
  AddRecoverEntityUseInformation(fpm, lifter_context);
  AddSinkSelectionsIntoBranchTargets(fpm);
  AddRemoveTrivialPhisAndSelects(fpm);

  fpm.addPass(llvm::DCEPass());
  //AddSimplifyStackArithFlags(fpm, options.stack_pointer_is_signed);
  AddRemoveStackPointerCExprs(fpm);
  AddRecoverStackFrameInformation(fpm, err_man, options);
  fpm.addPass(llvm::SROA());
  AddSplitStackFrameAtReturnAddress(fpm, err_man);
  fpm.addPass(llvm::SROA());
  AddBranchRecovery(fpm);


  // Sometimes we have a values in the form of (expr ^ 1) used as branch
  // conditions or other targets. Try to fix these to be CMPs, since it
  // makes code easier to read and analyze. This is a fairly narrow optimization
  // but it comes up often enough for lifted code.
  AddConvertXorToCmp(fpm);

  if (FLAGS_pointer_brighten_gas) {
    AddBrightenPointerOperations(fpm, FLAGS_pointer_brighten_gas);
  }


  pb.crossRegisterProxies(lam, fam, cam, mam);

  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
  mpm.run(module, mam);

  // We can extend error handling here to provide more visibility
  // into what has happened
  for (const auto &error : err_man.ErrorList()) {
    std::stringstream buffer;
    buffer << error.description;

    // If this is a fatal error, also include the module IR if
    // available, both before and after the transformation
    if (error.severity == SeverityType::Fatal) {
      buffer << "\n";

      if (error.func_before.has_value()) {
        buffer << "Module IR before the transformation follows\n";
        buffer << error.func_before.value();
      } else {
        buffer << "No pre-transformation module IR available.";
      }

      buffer << "\n";

      if (error.func_after.has_value()) {
        buffer << "Module IR after the transformation follows\n";
        buffer << error.func_after.value();
      } else {
        buffer << "No post-transformation module IR available.";
      }
    }

    auto message = buffer.str();

    // TODO: Maybe create a structured JSON report instead?
    switch (error.severity) {
      case SeverityType::Information: LOG(INFO) << message; break;
      case SeverityType::Warning: LOG(WARNING) << message; break;
      case SeverityType::Error: LOG(ERROR) << message; break;
      case SeverityType::Fatal: LOG(FATAL) << message; break;
    }
  }

  CHECK(!err_man.HasFatalError());


  llvm::FunctionPassManager second_fpm;


  AddTransformRemillJumpIntrinsics(second_fpm, lifter_context);
  AddRemoveRemillFunctionReturns(second_fpm, lifter_context);
  AddLowerRemillUndefinedIntrinsics(second_fpm);
  AddRemoveFailedBranchHints(second_fpm);
  second_fpm.addPass(CodeQualityStatCollector());



  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(second_fpm)));
  mpm.run(module, mam);

  // Get rid of all final uses of `__anvill_pc`.
  if (auto anvill_pc = module.getGlobalVariable(::anvill::kSymbolicPCName)) {
    remill::ReplaceAllUsesOfConstant(
        anvill_pc, llvm::Constant::getNullValue(anvill_pc->getType()), &module);
  }

  CHECK(remill::VerifyModule(&module));

  // manually clear the analyses to prevent ASAN failures in the destructor
  mam.clear();
  fam.clear();
  cam.clear();
  lam.clear();
}

}  // namespace anvill
