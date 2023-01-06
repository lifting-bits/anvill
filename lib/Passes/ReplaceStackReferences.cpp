#include <anvill/CrossReferenceFolder.h>
#include <anvill/CrossReferenceResolver.h>
#include <anvill/Passes/ReplaceStackReferences.h>
#include <glog/logging.h>
#include <llvm/ADT/IntervalMap.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "anvill/Declarations.h"
namespace anvill {


llvm::StringRef ReplaceStackReferences::name(void) {
  return "Replace stack references";
}


// Contains a list of `load` and `store` instructions that reference
// the stack pointer
using StackPointerRegisterUsages = std::vector<llvm::Use *>;

// Enumerates all the store and load instructions that reference
// the stack
static StackPointerRegisterUsages
EnumerateStackPointerUsages(llvm::Function &function) {
  StackPointerRegisterUsages output;
  StackPointerResolver sp_resolver(function.getParent());

  for (auto &basic_block : function) {
    for (auto &instr : basic_block) {
      for (auto i = 0u, num_ops = instr.getNumOperands(); i < num_ops; ++i) {
        auto &use = instr.getOperandUse(i);
        if (auto val = use.get(); llvm::isa<llvm::Constant>(val) &&
                                  sp_resolver.IsRelatedToStackPointer(val)) {
          output.emplace_back(&use);
        }
      }
    }
  }

  return output;
}


struct BasicBlockVar {
  size_t index;
  ParameterDecl decl;
};


struct StackVariable {
  // offset into this variable
  std::int64_t offset;
  BasicBlockVar decl;
};

class StackModel {
 private:
  std::map<std::int64_t, BasicBlockVar> frame;
  const remill::Arch *arch;

 public:
  uint64_t GetParamDeclSize(const ParameterDecl &decl) {
    CHECK(arch->DataLayout().getTypeSizeInBits(decl.type) != 0);
    return arch->DataLayout().getTypeSizeInBits(decl.type) / 8;
  }

  StackModel(const BasicBlockContext &cont, const remill::Arch *arch) {
    this->arch = arch;
    size_t index = 0;
    // this feels weird maybe it should be all stack variables but then if the variable isnt live...
    // we will have discovered something that should have been live.
    for (const auto &v : cont.LiveParamsAtEntryAndExit()) {
      if (v.param.mem_reg &&
          v.param.mem_reg->name == arch->StackPointerRegisterName()) {
        this->InsertFrameVar(index, v.param);
      }
      index += 1;
    }
  }


  std::optional<BasicBlockVar> GetParamLte(std::int64_t off) {
    auto prec = this->frame.lower_bound(off);
    if (prec == this->frame.end()) {
      return std::nullopt;
    }

    if (prec->first == off) {
      return {prec->second};
    }

    if (prec == this->frame.begin()) {
      return std::nullopt;
    }


    auto prev_decl = (--prec)->second;
    CHECK(prev_decl.decl.mem_offset <= off);
    return {prev_decl};
  }

  std::optional<StackVariable> GetOverlappingParam(std::int64_t off) {
    auto vlte = GetParamLte(off);

    if (!vlte.has_value()) {
      return std::nullopt;
    }

    auto offset_into_var = off - vlte->decl.mem_offset;
    if (offset_into_var < static_cast<std::int64_t>(
                              vlte->decl.type->getPrimitiveSizeInBits() / 8)) {
      return {{offset_into_var, *vlte}};
    }

    return std::nullopt;
  }


  bool VarOverlaps(std::int64_t off) {


    return GetOverlappingParam(off).has_value();
  }


  void InsertFrameVar(size_t index, ParameterDecl var) {
    if (VarOverlaps(var.mem_offset) ||
        VarOverlaps(var.mem_offset + GetParamDeclSize(var) - 1)) {

      auto oparam = GetOverlappingParam(var.mem_offset);
      if (!VarOverlaps(var.mem_offset)) {
        oparam =
            GetOverlappingParam(var.mem_offset + GetParamDeclSize(var) - 1);
      }

      LOG(FATAL) << "Inserting variable that overlaps with current frame "
                 << var.mem_offset << " with size: " << GetParamDeclSize(var)
                 << " Overlaps with " << oparam->decl.decl.mem_offset
                 << " with size " << GetParamDeclSize(oparam->decl.decl);
    }

    this->frame.insert({var.mem_offset, {index, var}});
  }
};

llvm::PreservedAnalyses ReplaceStackReferences::runOnBasicBlockFunction(
    llvm::Function &F, llvm::FunctionAnalysisManager &AM,
    const BasicBlockContext &cont) {
  NullCrossReferenceResolver resolver;
  CrossReferenceFolder folder(resolver, this->lifter.DataLayout());
  StackModel smodel(cont, this->lifter.Options().arch);

  std::vector<std::pair<llvm::Use *, BasicBlockVar>> to_replace_vars;

  for (auto use : EnumerateStackPointerUsages(F)) {
    const auto reference = folder.TryResolveReferenceWithCaching(use->get());
    if (!reference.is_valid || !reference.references_stack_pointer) {
      continue;
    }

    // The offset from the stack pointer. Force to a 32-bit, then sign-extend.
    int64_t stack_offset = reference.Displacement(this->lifter.DataLayout());

    auto referenced_variable = smodel.GetOverlappingParam(stack_offset);
    //TODO(Ian) handle nonzero offset
    if (referenced_variable.has_value() && referenced_variable->offset == 0 &&
        llvm::isa<llvm::PointerType>(use->get()->getType())) {
      to_replace_vars.push_back({use, referenced_variable->decl});
    }
  }

  for (auto [use, v] : to_replace_vars) {
    llvm::IRBuilder<> ir(&F.getEntryBlock(), F.getEntryBlock().begin());
    if (auto *insn = llvm::dyn_cast<llvm::Instruction>(use->get())) {
      ir.SetInsertPoint(insn);
    }

    auto g = anvill::ProvidePointerFromFunctionArgs(
        &F, v.index, this->lifter.Options(), cont);
    use->set(g);
  }
  CHECK(!llvm::verifyFunction(F, &llvm::errs()));

  return to_replace_vars.empty() ? llvm::PreservedAnalyses::all()
                                 : llvm::PreservedAnalyses::none();
}
}  // namespace anvill