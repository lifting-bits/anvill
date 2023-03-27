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
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Pass.h>
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
#include <llvm/Passes/OptimizationLevel.h>
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
#include <llvm/Analysis/TargetLibraryInfo.h>

#include <anvill/Providers.h>
#include <anvill/Passes/JumpTableAnalysis.h>
#include <anvill/Passes/CodeQualityStatCollector.h>
#include <anvill/Passes/BranchAnalysis.h>
#include <anvill/Passes/JumpTableAnalysis.h>
#include <anvill/Passes/ReplaceRemillFunctionReturnsWithAnvillFunctionReturns.h>
// clang-format on

#include <anvill/ABI.h>
#include <anvill/CrossReferenceResolver.h>
#include <anvill/Declarations.h>
#include <anvill/Lifters.h>
#include <anvill/Passes/ConvertPointerArithmeticToGEP.h>
#include <anvill/Passes/InlineBasicBlockFunctions.h>
#include <anvill/Passes/JumpTableAnalysis.h>
#include <anvill/Passes/RemoveAssignmentsToNextPC.h>
#include <anvill/Passes/RemoveCallIntrinsics.h>
#include <anvill/Passes/ReplaceStackReferences.h>
#include <anvill/Providers.h>
#include <anvill/Transforms.h>
#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Error.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>

#include <unordered_set>
#include <vector>

#include "anvill/Passes/RemoveAnvillReturns.h"
#include "anvill/Passes/SplitStackFrameAtReturnAddress.h"
#include "anvill/Specification.h"

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
  inline explicit OurVerifierPass(unsigned line_) : line(line_) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::AnalysisManager<llvm::Function> &AM) {
    LOG(ERROR) << "Verifier at " << line;
    return pass.run(F, AM);
  }
};

// Optimize a module. This can be a module with semantics code, lifted
// code, etc.
// When utilizing crossRegisterProxies cleanup triggers asan

void OptimizeModule(const EntityLifter &lifter, llvm::Module &module,
                    const BasicBlockContexts &contexts,
                    const anvill::Specification &spec) {


  CHECK(!llvm::verifyModule(module, &llvm::errs()));
  const LifterOptions &options = lifter.Options();

  EntityCrossReferenceResolver xr(lifter);

  if (auto err = module.materializeAll(); remill::IsError(err)) {
    LOG(FATAL) << remill::GetErrorString(err);
  }

  /*
  if (auto used = module.getGlobalVariable("llvm.used"); used) {
    used->setLinkage(llvm::GlobalValue::PrivateLinkage);
    used->eraseFromParent();
  }

  if (auto used = module.getGlobalVariable("llvm.compiler.used"); used) {
    used->setLinkage(llvm::GlobalValue::PrivateLinkage);
    used->eraseFromParent();
  }*/

  LOG(INFO) << "Optimizing module.";

  if (auto memory_escape = module.getFunction(kMemoryPointerEscapeFunction)) {
    for (auto call : remill::CallersOf(memory_escape)) {
      call->eraseFromParent();
    }
    memory_escape->eraseFromParent();
  }

  CHECK(remill::VerifyModule(&module));

  std::optional<unsigned> pc_metadata_id;
  if (options.pc_metadata_name) {
    auto &context = options.module->getContext();
    pc_metadata_id = context.getMDKindID(options.pc_metadata_name);
  }

  ConvertPointerArithmeticToGEP::StructMap structs;
  ConvertPointerArithmeticToGEP::TypeMap types;
  ConvertPointerArithmeticToGEP::MDMap md;

  llvm::PassBuilder pb;
  llvm::ModulePassManager mpm;
  llvm::ModuleAnalysisManager mam;
  llvm::LoopAnalysisManager lam;
  llvm::CGSCCAnalysisManager cam;
  //  llvm::InlineParams params;
  llvm::FunctionAnalysisManager fam;

  llvm::Triple ModuleTriple(module.getTargetTriple());
  llvm::TargetLibraryInfoImpl TLII(ModuleTriple);
  TLII.disableAllFunctions();
  fam.registerPass([&] { return llvm::TargetLibraryAnalysis(TLII); });
  pb.registerFunctionAnalyses(fam);
  pb.registerModuleAnalyses(mam);
  pb.registerCGSCCAnalyses(cam);
  pb.registerLoopAnalyses(lam);

  fam.registerPass([&] { return BranchAnalysis(); });
  fam.registerPass([&] { return JumpTableAnalysis(lifter); });

  //  params.DefaultThreshold = 250;
  //  auto inliner = llvm::ModuleInlinerWrapperPass(params);
  //  mpm.addPass(std::move(inliner));

  mpm.addPass(llvm::GlobalOptPass());

  mpm.addPass(llvm::GlobalDCEPass());

  mpm.addPass(llvm::StripDeadDebugInfoPass());

  llvm::FunctionPassManager fpm;

  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::VerifierPass());
  // NOTE(alex): This pass is extremely slow with LLVM 14.
  // fpm.addPass(llvm::SinkingPass());

  // NewGVN has bugs with `____strtold_l_internal` from chal5, amd64.
  fpm.addPass(llvm::NewGVNPass());
  fpm.addPass(llvm::VerifierPass());

  fpm.addPass(llvm::SCCPPass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::DSEPass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::SROAPass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::EarlyCSEPass(true));
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::BDCEPass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::SimplifyCFGPass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::SinkingPass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::SimplifyCFGPass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::InstCombinePass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(anvill::ReplaceRemillFunctionReturnsWithAnvillFunctionReturns(
      contexts, lifter));
  fpm.addPass(llvm::VerifierPass());
  AddSinkSelectionsIntoBranchTargets(fpm);
  fpm.addPass(llvm::VerifierPass());
  AddRemoveUnusedFPClassificationCalls(fpm);
  fpm.addPass(llvm::VerifierPass());
  AddRemoveDelaySlotIntrinsics(fpm);
  fpm.addPass(llvm::VerifierPass());
  AddRemoveErrorIntrinsics(fpm);
  fpm.addPass(llvm::VerifierPass());
  AddLowerRemillMemoryAccessIntrinsics(fpm);
  fpm.addPass(llvm::VerifierPass());
  AddRemoveCompilerBarriers(fpm);

  fpm.addPass(llvm::VerifierPass());
  // TODO(pag): This pass has an issue on the `SMIME_write_ASN1` function
  //            of the ARM64 variant of Challenge 5.
  // AddHoistUsersOfSelectsAndPhis(fpm);

  fpm.addPass(llvm::InstCombinePass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::SROAPass());
  fpm.addPass(llvm::VerifierPass());

  // Sometimes we observe patterns where PC- and SP-related offsets are
  // accidentally truncated, and thus displacement-based analyses make them
  // look like really big 32-bit values, when really they are small negative
  // numbers that have been truncated and should have always been small 64-bit
  // negative numbers. Thus, we want to fixup such cases prior to any kind of
  // stack analysis.
  AddConvertMasksToCasts(fpm);
  fpm.addPass(llvm::VerifierPass());
  AddSinkSelectionsIntoBranchTargets(fpm);
  fpm.addPass(llvm::VerifierPass());
  AddRemoveTrivialPhisAndSelects(fpm);
  fpm.addPass(llvm::VerifierPass());

  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::VerifierPass());
  AddRemoveStackPointerCExprs(fpm, options.stack_frame_recovery_options);
  fpm.addPass(llvm::VerifierPass());
  //AddRecoverBasicStackFrame(fpm, options.stack_frame_recovery_options);
  //AddSplitStackFrameAtReturnAddress(fpm, options.stack_frame_recovery_options);
  fpm.addPass(llvm::SROAPass());
  //fpm.addPass(anvill::ReplaceStackReferences(contexts, lifter));
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::SROAPass());
  fpm.addPass(llvm::VerifierPass());

  AddCombineAdjacentShifts(fpm);
  fpm.addPass(llvm::VerifierPass());

  // Sometimes we have a values in the form of (expr ^ 1) used as branch
  // conditions or other targets. Try to fix these to be CMPs, since it
  // makes code easier to read and analyze. This is a fairly narrow optimization
  // but it comes up often enough for lifted code.


  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(anvill::RemoveCallIntrinsics(xr, spec, lifter));
  fpm.addPass(llvm::VerifierPass());
  fpm.addPass(llvm::SROAPass());
  fpm.addPass(llvm::VerifierPass());
  AddConvertAddressesToEntityUses(fpm, xr, pc_metadata_id);

  AddBranchRecovery(fpm);
  fpm.addPass(llvm::VerifierPass());

  fpm.addPass(ConvertPointerArithmeticToGEP(contexts, types, structs, md));
  fpm.addPass(llvm::VerifierPass());
  pb.crossRegisterProxies(lam, fam, cam, mam);

  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
  mpm.run(module, mam);

  llvm::FunctionPassManager second_fpm;

  AddTransformRemillJumpIntrinsics(second_fpm, xr);
  second_fpm.addPass(llvm::VerifierPass());
  second_fpm.addPass(anvill::ReplaceStackReferences(contexts, lifter));
  if (options.should_remove_assignments_to_next_pc) {
    second_fpm.addPass(anvill::RemoveAssignmentsToNextPC(contexts, lifter));
  }
  //AddRemoveRemillFunctionReturns(second_fpm, xr);
  //AddConvertSymbolicReturnAddressToConcreteReturnAddress(second_fpm);
  AddLowerRemillUndefinedIntrinsics(second_fpm);
  second_fpm.addPass(llvm::VerifierPass());
  AddRemoveFailedBranchHints(second_fpm);
  second_fpm.addPass(llvm::VerifierPass());
  second_fpm.addPass(llvm::NewGVNPass());
  second_fpm.addPass(llvm::VerifierPass());
  second_fpm.addPass(llvm::InstCombinePass());
  AddSpreadPCMetadata(second_fpm, options);


  second_fpm.addPass(llvm::VerifierPass());
  AddConvertAddressesToEntityUses(fpm, xr, pc_metadata_id);
  second_fpm.addPass(llvm::VerifierPass());
  AddConvertXorsToCmps(second_fpm);
  second_fpm.addPass(llvm::VerifierPass());
  second_fpm.addPass(llvm::DCEPass());
  second_fpm.addPass(llvm::VerifierPass());
  second_fpm.addPass(llvm::DSEPass());
  second_fpm.addPass(llvm::VerifierPass());


  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(second_fpm)));
  mpm.addPass(anvill::CodeQualityStatCollector());
  mpm.run(module, mam);

  // Get rid of all final uses of `__anvill_pc`.
  if (lifter.Options().should_remove_anvill_pc) {
    if (auto anvill_pc = module.getGlobalVariable(::anvill::kSymbolicPCName)) {
      remill::ReplaceAllUsesOfConstant(
          anvill_pc, llvm::Constant::getNullValue(anvill_pc->getType()),
          &module);
    }
  }

  if (lifter.Options().should_inline_basic_blocks) {
    llvm::FunctionPassManager inliner;

    inliner.addPass(InlineBasicBlockFunctions(contexts, lifter));

    llvm::ModulePassManager mpminliner;
    mpminliner.addPass(
        llvm::createModuleToFunctionPassAdaptor(std::move(inliner)));
    mpminliner.addPass(
        llvm::createModuleToPostOrderCGSCCPassAdaptor(llvm::InlinerPass()));
    llvm::FunctionPassManager rm_returns;
    rm_returns.addPass(anvill::RemoveAnvillReturns());

    mpminliner.addPass(
        llvm::createModuleToFunctionPassAdaptor(std::move(rm_returns)));

    mpminliner.run(module, mam);

    // lets make sure we eliminate all the basic block functions because we dont care anymore
    for (auto &f : module.getFunctionList()) {
      if (anvill::GetBasicBlockAddr(&f)) {
        f.setLinkage(llvm::GlobalValue::InternalLinkage);
      }
    }

    auto intrinsics = module.getFunction("__remill_intrinsics");
    if (intrinsics) {
      intrinsics->eraseFromParent();
    }


    auto defaultmpm =
        pb.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O3);

    defaultmpm.run(module, mam);

    llvm::createModuleToFunctionPassAdaptor(
        SplitStackFrameAtReturnAddress(options.stack_frame_recovery_options))
        .run(module, mam);


    pb.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O3)
        .run(module, mam);
  }


  // Manually clear the analyses to prevent ASAN failures in the destructors.
  mam.clear();
  fam.clear();
  cam.clear();
  lam.clear();

  CHECK(remill::VerifyModule(&module));
}

}  // namespace anvill
