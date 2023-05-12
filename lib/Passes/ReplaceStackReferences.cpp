#include <anvill/CrossReferenceFolder.h>
#include <anvill/CrossReferenceResolver.h>
#include <anvill/Passes/ReplaceStackReferences.h>
#include <glog/logging.h>
#include <llvm/ADT/APInt.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/IntervalMap.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>

#include <cstdint>
#include <map>
#include <optional>
#include <variant>
#include <vector>

#include "anvill/Declarations.h"
#include "anvill/Utils.h"

namespace anvill {

namespace {

class StackCrossReferenceResolver : public CrossReferenceFolder {
 private:
  const llvm::DataLayout &dl;
  const AbstractStack &abs_stack;

  ResolvedCrossReference StackPtrToXref(std::int64_t off) const {
    ResolvedCrossReference rxref;
    rxref.is_valid = true;
    rxref.references_stack_pointer = true;
    rxref.size = dl.getPointerSizeInBits(0);
    rxref.u.displacement = off;
    return rxref;
  }

 public:
  StackCrossReferenceResolver(const CrossReferenceResolver &resolver,
                              const llvm::DataLayout &dl,
                              const AbstractStack &abs_stack)
      : CrossReferenceFolder(resolver, dl),
        dl(dl),
        abs_stack(abs_stack) {}

 protected:
  virtual std::optional<ResolvedCrossReference>
  ResolveValueCallback(llvm::Value *v) const override {
    DLOG(INFO) << "Looking at: " << remill::LLVMThingToString(v);
    auto stack_ref = abs_stack.StackPointerFromStackCompreference(v);
    if (stack_ref) {
      return this->StackPtrToXref(*stack_ref);
    }

    return std::nullopt;
  }
};


std::optional<llvm::Value *>
GetPtrToOffsetInto(llvm::IRBuilder<> &ir, const llvm::DataLayout &dl,
                   llvm::Type *deref_type, llvm::Value *ptr,
                   size_t offset_into_type) {
  if (offset_into_type == 0) {
    return ptr;
  }


  llvm::APInt ap_off(64, offset_into_type, false);
  auto elem_type = deref_type;
  auto index = dl.getGEPIndexForOffset(elem_type, ap_off);

  if (!index) {
    return std::nullopt;
  }
  auto i32 = llvm::IntegerType::getInt32Ty(deref_type->getContext());
  return ir.CreateGEP(
      deref_type, ptr,
      {llvm::ConstantInt::get(i32, 0),
       llvm::ConstantInt::get(llvm::IntegerType::get(deref_type->getContext(),
                                                     index->getBitWidth()),
                              *index)});
}
}  // namespace

llvm::StringRef ReplaceStackReferences::name(void) {
  return "Replace stack references";
}


// Contains a list of `load` and `store` instructions that reference
// the stack pointer
using StackPointerRegisterUsages = std::vector<llvm::Use *>;

// Enumerates all the store and load instructions that reference
// the stack
static StackPointerRegisterUsages
EnumerateStackPointerUsages(llvm::Function &function,
                            llvm::ArrayRef<llvm::Value *> additional_sps) {
  StackPointerRegisterUsages output;
  StackPointerResolver sp_resolver(function.getParent(), additional_sps);

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

  StackModel(const BasicBlockContext &cont, const remill::Arch *arch,
             const AbstractStack &abs_stack) {
    this->arch = arch;
    size_t index = 0;
    // this feels weird maybe it should be all stack variables but then if the variable isnt live...
    // we will have discovered something that should have been live.
    for (const auto &v : cont.LiveParamsAtEntryAndExit()) {
      if (HasMemLoc(v.param) && v.param.oredered_locs.size() == 1 &&
          v.param.oredered_locs[0].mem_reg->name ==
              arch->StackPointerRegisterName()) {
        this->InsertFrameVar(index, v.param);
      }
      index += 1;
    }
  }


  std::optional<BasicBlockVar> GetParamLte(std::int64_t off) {
    auto prec = this->frame.lower_bound(off);
    if (prec == this->frame.end()) {
      if (this->frame.begin() != this->frame.end() &&
          this->frame.begin()->first <= off) {
        return this->frame.begin()->second;
      }
      return std::nullopt;
    }

    if (prec->first == off) {
      return {prec->second};
    }

    if (prec == this->frame.begin()) {
      return std::nullopt;
    }


    auto prev_decl = (--prec)->second;
    CHECK(prev_decl.decl.oredered_locs[0].mem_offset <= off);
    return {prev_decl};
  }

  std::optional<StackVariable> GetOverlappingParam(std::int64_t off) {

    auto vlte = GetParamLte(off);

    if (!vlte.has_value()) {
      return std::nullopt;
    }

    DLOG(INFO) << "value found lte offset: "
               << vlte->decl.oredered_locs[0].mem_offset << " " << off;

    auto offset_into_var = off - vlte->decl.oredered_locs[0].mem_offset;
    if (offset_into_var <
        static_cast<std::int64_t>(GetParamDeclSize(vlte->decl))) {
      return {{offset_into_var, *vlte}};
    }
    DLOG(INFO) << "Looking for off  " << off << " but not fitting "
               << offset_into_var << " got off "
               << vlte->decl.oredered_locs[0].mem_offset;
    return std::nullopt;
  }


  bool VarOverlaps(std::int64_t off) {


    return GetOverlappingParam(off).has_value();
  }


  void InsertFrameVar(size_t index, ParameterDecl var) {
    if (VarOverlaps(var.oredered_locs[0].mem_offset) ||
        VarOverlaps(var.oredered_locs[0].mem_offset + GetParamDeclSize(var) -
                    1)) {

      auto oparam = GetOverlappingParam(var.oredered_locs[0].mem_offset);
      if (!VarOverlaps(var.oredered_locs[0].mem_offset)) {
        oparam = GetOverlappingParam(var.oredered_locs[0].mem_offset +
                                     GetParamDeclSize(var) - 1);
      }

      LOG(FATAL) << "Inserting variable that overlaps with current frame "
                 << var.oredered_locs[0].mem_offset
                 << " with size: " << GetParamDeclSize(var) << " Overlaps with "
                 << oparam->decl.decl.oredered_locs[0].mem_offset
                 << " with size " << GetParamDeclSize(oparam->decl.decl);
    }

    this->frame.insert({var.oredered_locs[0].mem_offset, {index, var}});
  }
};

llvm::PreservedAnalyses ReplaceStackReferences::runOnBasicBlockFunction(
    llvm::Function &F, llvm::FunctionAnalysisManager &AM,
    const BasicBlockContext &cont, const FunctionDecl &fdecl) {
  size_t overrunsz = cont.GetMaxStackSize() - cont.GetStackSize();
  llvm::IRBuilder<> ent_insert(&F.getEntryBlock(), F.getEntryBlock().begin());
  auto overrunptr = ent_insert.CreateAlloca(
      AbstractStack::StackTypeFromSize(F.getContext(), overrunsz));

  DLOG(INFO) << "Replacing stack vars in bb: " << std::hex
             << *anvill::GetBasicBlockAddr(&F);
  DLOG(INFO) << "Stack size " << cont.GetStackSize();
  DLOG(INFO) << "Max stack size " << cont.GetMaxStackSize();
  AbstractStack stk(
      F.getContext(),
      {{cont.GetStackSize(), anvill::GetBasicBlockStackPtr(&F)},
       {overrunsz, overrunptr}},
      lifter.Options().stack_frame_recovery_options.stack_grows_down,
      cont.GetPointerDisplacement());

  StackModel smodel(cont, this->lifter.Options().arch, stk);

  NullCrossReferenceResolver resolver;
  StackCrossReferenceResolver folder(resolver, this->lifter.DataLayout(), stk);

  // TODO(Ian): do a fixed size here
  std::vector<std::pair<llvm::Use *, std::variant<llvm::Value *, std::int64_t>>>
      to_replace_vars;

  auto collision = false;
  // TODO(Ian): also handle resolving from references where the base is inside a bb var
  for (auto use :
       EnumerateStackPointerUsages(F, {anvill::GetBasicBlockStackPtr(&F)})) {
    const auto reference = folder.TryResolveReferenceWithCaching(use->get());
    if (!reference.is_valid || !reference.references_stack_pointer) {
      continue;
    }

    // The offset from the stack pointer. Force to a 32-bit, then sign-extend.
    int64_t stack_offset = reference.Displacement(this->lifter.DataLayout());

    auto referenced_variable = smodel.GetOverlappingParam(stack_offset);

    //TODO(Ian) handle nonzero offset
    if (referenced_variable.has_value()) {

      auto g = cont.ProvidePointerFromFunctionArgs(
          &F, referenced_variable->decl.decl);
      auto ptr = GetPtrToOffsetInto(ent_insert, this->lifter.DataLayout(),
                                    referenced_variable->decl.decl.type, g,
                                    referenced_variable->offset);
      if (ptr) {
        to_replace_vars.push_back({use, *ptr});
        continue;
      }
      LOG(ERROR) << "Couldnt create a pointer for offset "
                 << referenced_variable->offset << " into a "
                 << remill::LLVMThingToString(
                        referenced_variable->decl.decl.type);
      collision = true;
    }

    DLOG(INFO) << "Escaping stack access " << stack_offset << " "
               << remill::LLVMThingToString(use->get());

    // otherwise we are going to escape the abstract stack
    to_replace_vars.push_back({use, stack_offset});
  }

  if (to_replace_vars.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  for (auto [use, v] : to_replace_vars) {
    auto use_of_variable = use;
    auto replace_use = [use_of_variable, overrunptr](llvm::Value *with_ptr) {
      if (llvm::isa<llvm::PointerType>(use_of_variable->get()->getType())) {
        use_of_variable->set(with_ptr);
      } else if (llvm::isa<llvm::IntegerType>(
                     use_of_variable->get()->getType())) {

        llvm::IRBuilder<> ir(overrunptr);

        if (auto ptr = llvm::dyn_cast<llvm::Instruction>(with_ptr)) {
          ir.SetInsertPoint(ptr->getNextNode());
        }

        use_of_variable->set(
            ir.CreatePointerCast(with_ptr, use_of_variable->get()->getType()));
      }
    };
    if (std::holds_alternative<llvm::Value *>(v)) {
      replace_use(std::get<llvm::Value *>(v));
    } else {
      auto offset = std::get<int64_t>(v);
      auto ptr = stk.PointerToStackMemberFromOffset(ent_insert, offset);
      if (ptr) {
        replace_use(*ptr);
      } else {
        LOG(ERROR) << "No pointer for offset " << offset;
        auto off = stk.StackOffsetFromStackPointer(offset);
        if (off) {
          LOG(ERROR) << "Was supposed to use offset " << *off;
        }
      }
    }
  }

  DCHECK(!llvm::verifyFunction(F, &llvm::errs()));


  // This isnt a sound check at all we could still derive a pointer to a variable from another variable. Essentially need to check that all
  // derivations are in bounds...
  if (EnumerateStackPointerUsages(F, {}).empty() && !collision) {
    auto noalias =
        llvm::Attribute::get(F.getContext(), llvm::Attribute::NoAlias);

    // Note(Ian): the theory here is if all stack references are resolved, then any
    // pointer use of the stack only derives from unresolved offsets
    // TODO(Ian): this isnt sound if the resolved stack pointer then has further manipulation causing it to land inside a variable
    anvill::GetBasicBlockStackPtr(&F)->addAttr(noalias);

    for (auto &param : cont.GetParams()) {
      cont.ProvidePointerFromFunctionArgs(&F, param)->addAttr(noalias);
    }
  }

  return to_replace_vars.empty() ? llvm::PreservedAnalyses::all()
                                 : llvm::PreservedAnalyses::none();
}
}  // namespace anvill
