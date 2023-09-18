#include "CodeLifter.h"

#include <anvill/ABI.h>
#include <anvill/Type.h>
#include <glog/logging.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Pass.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/StandardInstrumentations.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/DeadStoreElimination.h>
#include <llvm/Transforms/Scalar/Reassociate.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>
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


CodeLifter::CodeLifter(const LifterOptions &options,
                       llvm::Module *semantics_module,
                       const TypeTranslator &type_specifier)
    : options(options),
      semantics_module(semantics_module),
      intrinsics(semantics_module),
      llvm_context(semantics_module->getContext()),
      op_lifter(options.arch->DefaultLifter(intrinsics)),
      is_sparc(options.arch->IsSPARC32() || options.arch->IsSPARC64()),
      is_x86_or_amd64(options.arch->IsX86() || options.arch->IsAMD64()),
      pc_reg(options.arch
                 ->RegisterByName(options.arch->ProgramCounterRegisterName())
                 ->EnclosingRegister()),
      sp_reg(
          options.arch->RegisterByName(options.arch->StackPointerRegisterName())
              ->EnclosingRegister()),
      memory_provider(options.memory_provider),
      type_provider(options.type_provider),
      type_specifier(type_specifier),
      address_type(
          llvm::Type::getIntNTy(llvm_context, options.arch->address_size)),
      i8_type(llvm::Type::getInt8Ty(llvm_context)),
      i8_zero(llvm::Constant::getNullValue(i8_type)),
      i32_type(llvm::Type::getInt32Ty(llvm_context)),
      mem_ptr_type(
          llvm::dyn_cast<llvm::PointerType>(remill::RecontextualizeType(
              options.arch->MemoryPointerType(), llvm_context))),
      state_ptr_type(
          llvm::dyn_cast<llvm::PointerType>(remill::RecontextualizeType(
              options.arch->StatePointerType(), llvm_context))),
      pc_reg_type(pc_reg->type) {
  if (options.pc_metadata_name) {
    pc_annotation_id = llvm_context.getMDKindID(options.pc_metadata_name);
  }
}

// Perform architecture-specific initialization of the state structure
// in `block`.
void CodeLifter::ArchSpecificStateStructureInitialization(
    llvm::BasicBlock *block, llvm::Value *new_state_ptr) {

  if (is_x86_or_amd64) {
    llvm::IRBuilder<> ir(block);

    const auto ssbase_reg = options.arch->RegisterByName("SSBASE");
    const auto fsbase_reg = options.arch->RegisterByName("FSBASE");
    const auto gsbase_reg = options.arch->RegisterByName("GSBASE");
    const auto dsbase_reg = options.arch->RegisterByName("DSBASE");
    const auto esbase_reg = options.arch->RegisterByName("ESBASE");
    const auto csbase_reg = options.arch->RegisterByName("CSBASE");

    if (gsbase_reg) {
      const auto gsbase_val = llvm::ConstantExpr::getPtrToInt(
          llvm::ConstantExpr::getAddrSpaceCast(
              llvm::ConstantExpr::getNullValue(
                  llvm::PointerType::get(block->getContext(), 256)),
              llvm::PointerType::get(block->getContext(), 0)),
          pc_reg_type);
      ir.CreateStore(gsbase_val, gsbase_reg->AddressOf(new_state_ptr, ir));
    }

    if (fsbase_reg) {
      const auto fsbase_val = llvm::ConstantExpr::getPtrToInt(
          llvm::ConstantExpr::getAddrSpaceCast(
              llvm::ConstantExpr::getNullValue(
                  llvm::PointerType::get(block->getContext(), 257)),
              llvm::PointerType::get(block->getContext(), 0)),
          pc_reg_type);
      ir.CreateStore(fsbase_val, fsbase_reg->AddressOf(new_state_ptr, ir));
    }

    if (ssbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     ssbase_reg->AddressOf(new_state_ptr, ir));
    }

    if (dsbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     dsbase_reg->AddressOf(new_state_ptr, ir));
    }

    if (esbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     esbase_reg->AddressOf(new_state_ptr, ir));
    }

    if (csbase_reg) {
      ir.CreateStore(llvm::Constant::getNullValue(pc_reg_type),
                     csbase_reg->AddressOf(new_state_ptr, ir));
    }
  }
}


// Initialize the state structure with default values, loaded from global
// variables. The purpose of these global variables is to show that there are
// some unmodelled external dependencies inside of a lifted function.
void CodeLifter::InitializeStateStructureFromGlobalRegisterVariables(
    llvm::BasicBlock *block, llvm::Value *state_ptr) {

  // Get or create globals for all top-level registers. The idea here is that
  // the spec could feasibly miss some dependencies, and so after optimization,
  // we'll be able to observe uses of `__anvill_reg_*` globals, and handle
  // them appropriately.

  llvm::IRBuilder<> ir(block);

  options.arch->ForEachRegister([=, &ir](const remill::Register *reg_) {
    if (auto reg = reg_->EnclosingRegister();
        reg_ == reg && reg != sp_reg && reg != pc_reg) {

      std::stringstream ss;
      ss << kUnmodelledRegisterPrefix << reg->name;
      const auto reg_name = ss.str();

      auto reg_global = semantics_module->getGlobalVariable(reg_name);
      if (!reg_global) {
        reg_global = new llvm::GlobalVariable(
            *semantics_module, reg->type, false,
            llvm::GlobalValue::ExternalLinkage, nullptr, reg_name);
      }

      const auto reg_ptr = reg->AddressOf(state_ptr, block);
      ir.CreateStore(ir.CreateLoad(reg->type, reg_global), reg_ptr);
    }
  });
}

llvm::Function *CodeLifter::GetTypeHintFunction() {
  const auto &func_name = kTypeHintFunctionPrefix;

  auto func = semantics_module->getFunction(func_name);
  if (func != nullptr) {
    return func;
  }

  auto ptr = llvm::PointerType::get(this->semantics_module->getContext(), 0);
  llvm::Type *func_parameters[] = {ptr};

  auto func_type = llvm::FunctionType::get(ptr, func_parameters, false);

  func = llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                                func_name, this->semantics_module);

  return func;
}

llvm::MDNode *CodeLifter::GetAddrAnnotation(uint64_t addr,
                                            llvm::LLVMContext &context) const {
  auto pc_val = llvm::ConstantInt::get(
      remill::RecontextualizeType(address_type, context), addr);
  auto pc_md = llvm::ValueAsMetadata::get(pc_val);
  return llvm::MDNode::get(context, pc_md);
}

// Allocate and initialize the state structure.
llvm::Value *
CodeLifter::AllocateAndInitializeStateStructure(llvm::BasicBlock *block,
                                                const remill::Arch *arch) {
  llvm::IRBuilder<> ir(block);
  const auto state_type = arch->StateStructType();
  llvm::Value *new_state_ptr = nullptr;

  switch (options.state_struct_init_procedure) {
    case StateStructureInitializationProcedure::kNone:
      new_state_ptr = ir.CreateAlloca(state_type);
      break;
    case StateStructureInitializationProcedure::kZeroes:
      new_state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::Constant::getNullValue(state_type), new_state_ptr);
      break;
    case StateStructureInitializationProcedure::kUndef:
      new_state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::UndefValue::get(state_type), new_state_ptr);
      break;
    case StateStructureInitializationProcedure::kGlobalRegisterVariables:
      new_state_ptr = ir.CreateAlloca(state_type);
      InitializeStateStructureFromGlobalRegisterVariables(block, new_state_ptr);
      break;
    case StateStructureInitializationProcedure::
        kGlobalRegisterVariablesAndZeroes:
      new_state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::Constant::getNullValue(state_type), new_state_ptr);
      InitializeStateStructureFromGlobalRegisterVariables(block, new_state_ptr);
      break;
    case StateStructureInitializationProcedure::
        kGlobalRegisterVariablesAndUndef:
      new_state_ptr = ir.CreateAlloca(state_type);
      ir.CreateStore(llvm::UndefValue::get(state_type), new_state_ptr);
      InitializeStateStructureFromGlobalRegisterVariables(block, new_state_ptr);
      break;
  }

  ArchSpecificStateStructureInitialization(block, new_state_ptr);
  return new_state_ptr;
}

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


  DCHECK(!llvm::verifyFunction(*inf, &llvm::errs()));

  llvm::ModuleAnalysisManager mam;
  llvm::FunctionAnalysisManager fam;
  llvm::LoopAnalysisManager lam;
  llvm::CGSCCAnalysisManager cam;

  llvm::ModulePassManager mpm;
  llvm::FunctionPassManager fpm;

  llvm::PassInstrumentationCallbacks pic;
  llvm::StandardInstrumentations si(inf->getContext(),
                                    /*DebugLogging=*/options.debug_pm,
                                    /*VerifyEach=*/options.debug_pm);
  si.registerCallbacks(pic, &fam);

  llvm::PassBuilder pb(nullptr, llvm::PipelineTuningOptions(), std::nullopt,
                       &pic);
  pb.registerModuleAnalyses(mam);
  pb.registerFunctionAnalyses(fam);
  pb.registerLoopAnalyses(lam);
  pb.registerCGSCCAnalyses(cam);
  pb.crossRegisterProxies(lam, fam, cam, mam);

  fpm.addPass(llvm::SimplifyCFGPass());
  fpm.addPass(llvm::PromotePass());
  fpm.addPass(llvm::ReassociatePass());
  fpm.addPass(llvm::DSEPass());
  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::SROAPass(llvm::SROAOptions::ModifyCFG));
  fpm.addPass(llvm::DCEPass());
  fpm.addPass(llvm::InstCombinePass());

  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
  mpm.run(*inf->getParent(), mam);

  mam.clear();
  fam.clear();
  lam.clear();
  cam.clear();

  ClearVariableNames(inf);
}

}  // namespace anvill
