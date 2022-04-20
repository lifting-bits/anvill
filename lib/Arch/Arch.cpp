/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "Arch.h"

#include <anvill/Declarations.h>
#include <glog/logging.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <sstream>

namespace remill {
class Arch;
class IntrinsicTable;
struct Register;
}  // namespace remill

namespace anvill {
namespace {
static const std::string kInvalidArch{"Invalid architecture"};
}  // namespace

// Return true if the RegisterConstraint contains the named variant.
bool RegisterConstraint::ContainsVariant(const std::string &name) const {
  for (const auto &v : variants) {
    if (v.register_name == name) {
      return true;
    }
  }
  return false;
}

Result<CallingConvention::Ptr, std::string>
CallingConvention::CreateCCFromArch(const remill::Arch *arch) {
  switch (arch->arch_name) {
    case remill::kArchInvalid: {
      return kInvalidArch;
    }

    // NOTE: AVX does not affect X86 specification
    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
    case remill::kArchX86_SLEIGH:
      if (arch->os_name == remill::kOSmacOS ||
          arch->os_name == remill::kOSLinux ||
          arch->os_name == remill::kOSSolaris) {
        return CreateX86_C(arch);

      } else if (arch->os_name == remill::kOSWindows) {
        return CreateX86_StdCall(arch);

      } else {
        break;
      }

    // NOTE: AVX does not affect x86-64 specification
    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512:
    case remill::kArchAMD64_SLEIGH:
      if (arch->os_name == remill::kOSmacOS ||
          arch->os_name == remill::kOSLinux ||
          arch->os_name == remill::kOSSolaris) {
        return CreateX86_64_SysV(arch);
      } else {
        break;
      }

    case remill::kArchAArch32LittleEndian: return CreateAArch32_C(arch);
    case remill::kArchThumb2LittleEndian: return CreateAArch32_C(arch);
    case remill::kArchAArch64LittleEndian: return CreateAArch64_C(arch);

    case remill::kArchSparc32:
      if (arch->os_name == remill::kOSLinux ||
          arch->os_name == remill::kOSSolaris) {
        return CreateSPARC32_C(arch);
      } else {
        break;
      }

    case remill::kArchSparc64:
      if (arch->os_name == remill::kOSLinux ||
          arch->os_name == remill::kOSSolaris) {
        return CreateSPARC64_C(arch);
      } else {
        break;
      }

    // Fallthrough for unsupported architectures
    default: break;
  }

  const auto arch_name = remill::GetArchName(arch->arch_name);
  const auto os_name = remill::GetOSName(arch->os_name);
  std::stringstream ss;
  ss << "Unsupported architecture/OS pair: " << arch_name << " and " << os_name;
  return ss.str();
}

// Still need the arch to be passed in so we can create the calling convention
Result<CallingConvention::Ptr, std::string>
CallingConvention::CreateCCFromArchAndID(const remill::Arch *arch,
                                         llvm::CallingConv::ID cc_id) {
  switch (cc_id) {
    case llvm::CallingConv::C:
      if (arch->IsX86()) {
        return CreateX86_C(arch);
      } else if (arch->IsAMD64()) {
        return CreateX86_64_SysV(arch);
      } else if (arch->IsAArch64()) {
        return CreateAArch64_C(arch);
      } else if (arch->IsSPARC32()) {
        return CreateSPARC32_C(arch);
      } else if (arch->IsSPARC64()) {
        return CreateSPARC64_C(arch);
      }
      break;

    case llvm::CallingConv::X86_StdCall:
      if (arch->IsX86()) {
        return CreateX86_StdCall(arch);

      } else if (arch->IsAMD64()) {
        return CreateX86_C(arch);  // Ignored on AMD64.
      }
      break;

    case llvm::CallingConv::X86_FastCall:
      if (arch->IsX86()) {
        return CreateX86_FastCall(arch);

      } else if (arch->IsAMD64()) {
        return CreateX86_C(arch);  // Ignored on AMD64.
      }
      break;

    case llvm::CallingConv::X86_ThisCall:
      if (arch->IsX86()) {
        return CreateX86_ThisCall(arch);

      } else if (arch->IsAMD64()) {
        return CreateX86_C(arch);  // Ignored on AMD64.
      }
      break;

    case llvm::CallingConv::X86_64_SysV:
      if (arch->IsAMD64()) {
        return CreateX86_64_SysV(arch);
      } else {
        break;
      }

    default: break;
  }

  std::stringstream ss;
  ss << "Unsupported calling convention ID: " << static_cast<unsigned>(cc_id);
  return ss.str();
}

Result<FunctionDecl, std::string>
CallingConvention::AllocateSignature(llvm::Function &func) {
  FunctionDecl decl;
  decl.arch = arch;
  decl.type = func.getFunctionType();
  decl.is_variadic = func.isVarArg();
  decl.is_noreturn = func.hasFnAttribute(llvm::Attribute::NoReturn);
  decl.calling_convention = ID();

  auto maybe_decl = this->AllocateSignature(decl, func);
  if (remill::IsError(maybe_decl)) {
    return remill::GetErrorString(maybe_decl);
  } else {
    // Here we override the return type of the extern declaration to match how it was allocated
    // In the future instead of doing this we should store information about how to extract return values at the llvm
    // level into the abi returns.
    // TODO(ian): Dont dont do this.
    decl.OverrideFunctionTypeWithABIReturnLayout();
    decl.OverrideFunctionTypeWithABIParamLayout();
    return decl;
  }
}

// Try to recover parameter names using debug information. Otherwise, name the
// parameters with the form "param_x". The mapping of the return value is
// positional starting at 1.
std::vector<std::string> TryRecoverParamNames(const llvm::Function &function) {
  std::vector<std::string> param_names(
      function.getFunctionType()->getNumParams());

  auto i = 0u;
  for (auto &param : function.args()) {
    if (param.hasName()) {
      param_names[i] = param.getName().str();
    } else {
      param_names[i] = "param" + std::to_string(i);
    }
    ++i;
  }

  // Iterate through all the instructions and look for debug intrinsics that
  // give us debug information about the parameters. We need to do this because
  // arg.uses() and arg.users() both do not take into account debug intrinsics.
  for (auto &block : function) {
    for (auto &inst : block) {
      if (auto debug_inst = llvm::dyn_cast<llvm::DbgInfoIntrinsic>(&inst)) {
        if (auto value_intrin = llvm::dyn_cast<llvm::DbgDeclareInst>(&inst)) {
          const llvm::MDNode *mdn = value_intrin->getVariable();
          const llvm::DILocalVariable *div =
              llvm::cast<llvm::DILocalVariable>(mdn);

          // Make sure it is actually an argument
          if (div->isParameter() && div->getArg() <= param_names.size()) {
            const auto found_name = div->getName();
            if (!found_name.empty()) {
              param_names[div->getArg() - 1u] = found_name.data();
            }
          }
        } else if (auto value_intrin =
                       llvm::dyn_cast<llvm::DbgValueInst>(debug_inst)) {
          const llvm::MDNode *mdn = value_intrin->getVariable();
          const llvm::DILocalVariable *div =
              llvm::cast<llvm::DILocalVariable>(mdn);

          if (div->isParameter() && div->getArg() <= param_names.size()) {
            const auto found_name = div->getName();
            if (!found_name.empty()) {
              param_names[div->getArg() - 1u] = found_name.data();
            }
          }
        }
      }
    }
  }

  return param_names;
}

// Return a vector of register constraints, augmented to to support additional
// registers made available in AVX or AVX512.
std::vector<RegisterConstraint>
ApplyX86Ext(const std::vector<RegisterConstraint> &constraints,
            remill::ArchName arch_name) {

  const auto is_avx = remill::kArchAMD64_AVX == arch_name ||
                      remill::kArchX86_AVX == arch_name ||
                      remill::kArchAMD64_SLEIGH == arch_name ||
                      remill::kArchX86_SLEIGH == arch_name;

  const auto is_avx512 = remill::kArchAMD64_AVX512 == arch_name ||
                         remill::kArchX86_AVX512 == arch_name ||
                         remill::kArchAMD64_SLEIGH == arch_name ||
                         remill::kArchX86_SLEIGH == arch_name;

  std::vector<RegisterConstraint> ret;
  ret.reserve(constraints.size());


  for (const auto &c : constraints) {
    if (c.variants.size() == 1 &&
        c.variants.front().register_name.rfind("XMM", 0) == 0) {

      const auto &reg_name = c.variants.front().register_name;
      unsigned reg_num = 0u;

      if (reg_name.size() == 4) {  // E.g. `XMM0`.
        reg_num = reg_name[3] - '0';

      } else if (reg_name.size() == 5) {  // E.g. `XMM10`.
        reg_num = ((reg_name[3] - '0') * 10u) + (reg_name[4] - '0');
      }

      // Assuming the name of the register is of the form XMM_
      const auto reg_num_str = std::to_string(reg_num);

      if (is_avx) {
        ret.push_back(RegisterConstraint({
            VariantConstraint("XMM" + reg_num_str, kTypeFloatOrVec, kMaxBit128),
            VariantConstraint("YMM" + reg_num_str, kTypeFloatOrVec, kMaxBit256),
        }));

      } else if (is_avx512) {
        ret.push_back(RegisterConstraint({
            VariantConstraint("XMM" + reg_num_str, kTypeFloatOrVec, kMaxBit128),
            VariantConstraint("YMM" + reg_num_str, kTypeFloatOrVec, kMaxBit256),
            VariantConstraint("ZMM" + reg_num_str, kTypeFloatOrVec, kMaxBit512),
        }));

      } else {
        ret.push_back(c);
      }

    } else {

      // Just copy the constraint if it doesn't contain an interesting register
      ret.push_back(c);
    }
  }
  return ret;
}

// Select and return one of `basic`, `avx`, or `avx512` given `arch_name`.
const std::vector<RegisterConstraint> &
SelectX86Constraint(remill::ArchName arch_name,
                    const std::vector<RegisterConstraint> &basic,
                    const std::vector<RegisterConstraint> &avx,
                    const std::vector<RegisterConstraint> &avx512) {
  switch (arch_name) {
    case remill::kArchX86:
    case remill::kArchAMD64: return basic;
    case remill::kArchX86_AVX:
    case remill::kArchAMD64_AVX: return avx;
    default: return avx512;
  }
}

namespace {

class AArch32Arch;

class AArch32InstructionLifter final : public remill::InstructionLifter {
 public:
  remill::InstructionLifter::LifterPtr aarch32;
  remill::InstructionLifter::LifterPtr thumb2;

  remill::ArchName last_arch_name{remill::ArchName::kArchInvalid};

  AArch32InstructionLifter(const AArch32Arch *arch_,
                           const remill::IntrinsicTable &intrinsics_);

  // Lift a single instruction into a basic block. `is_delayed` signifies that
  // this instruction will execute within the delay slot of another instruction.
  remill::LiftStatus LiftIntoBlock(remill::Instruction &inst,
                                   llvm::BasicBlock *block,
                                   llvm::Value *state_ptr, bool is_delayed) {
    if (is_delayed) {
      return remill::LiftStatus::kLiftedLifterError;
    }

    if (inst.arch_name != last_arch_name) {
      ClearCache();
      aarch32->ClearCache();
      thumb2->ClearCache();
      last_arch_name = inst.arch_name;
    }

    if (inst.arch_name == remill::ArchName::kArchAArch32LittleEndian) {
      return aarch32->LiftIntoBlock(inst, block, state_ptr, is_delayed);

    } else if (inst.arch_name == remill::ArchName::kArchThumb2LittleEndian) {
      return thumb2->LiftIntoBlock(inst, block, state_ptr, is_delayed);

    } else {
      return remill::LiftStatus::kLiftedInvalidInstruction;
    }
  }
};

// Composite architecture.
class AArch32Arch final : public remill::Arch {
 public:
  ArchPtr aarch32;
  ArchPtr thumb2;
  const remill::ArchName preferred_arch;

  AArch32Arch(llvm::LLVMContext *context_, remill::OSName os_name_,
              remill::ArchName arch_name_)
      : remill::Arch(context_, os_name_,
                     remill::ArchName::kArchAArch32LittleEndian),
        aarch32(remill::Arch::Build(
            context, os_name, remill::ArchName::kArchAArch32LittleEndian)),
        thumb2(remill::Arch::Build(context, os_name,
                                   remill::ArchName::kArchThumb2LittleEndian)),
        preferred_arch(arch_name_) {

    CHECK_NOTNULL(aarch32.get());
    CHECK_NOTNULL(thumb2.get());

    CHECK_EQ(aarch32->StackPointerRegisterName(),
             thumb2->StackPointerRegisterName());

    CHECK_EQ(aarch32->ProgramCounterRegisterName(),
             thumb2->ProgramCounterRegisterName());

    CHECK_EQ(aarch32->DefaultCallingConv(), thumb2->DefaultCallingConv());

    // NOTE(pag): The triples are *not* the same.

    CHECK_EQ(aarch32->DataLayout().getStringRepresentation(),
             thumb2->DataLayout().getStringRepresentation());

    PopulateRegisterTable();
  }

  virtual ~AArch32Arch(void) = default;

  // Return the type of the state structure.
  llvm::StructType *StateStructType(void) const final {
    return aarch32->StateStructType();
  }

  // Pointer to a state structure type.
  llvm::PointerType *StatePointerType(void) const final {
    return aarch32->StatePointerType();
  }

  // The type of memory.
  llvm::PointerType *MemoryPointerType(void) const final {
    return aarch32->MemoryPointerType();
  }

  // Return the type of a lifted function.
  llvm::FunctionType *LiftedFunctionType(void) const final {
    return aarch32->LiftedFunctionType();
  }

  // Apply `cb` to every register.
  void ForEachRegister(
      std::function<void(const remill::Register *)> cb) const final {
    return aarch32->ForEachRegister(std::move(cb));
  }

  // Return information about the register at offset `offset` in the `State`
  // structure.
  const remill::Register *RegisterAtStateOffset(uint64_t offset) const final {
    return aarch32->RegisterAtStateOffset(offset);
  }

  // Return information about a register, given its name.
  const remill::Register *RegisterByName(std::string_view name) const final {
    return aarch32->RegisterByName(name);
  }

  // Returns the name of the stack pointer register.
  std::string_view StackPointerRegisterName(void) const final {
    return aarch32->StackPointerRegisterName();
  }

  // Returns the name of the program counter register.
  std::string_view ProgramCounterRegisterName(void) const final {
    return aarch32->ProgramCounterRegisterName();
  }

  // Decode an instruction.
  bool DecodeInstruction(uint64_t address, std::string_view instr_bytes,
                         remill::Instruction &inst) const final {
    if (inst.in_delay_slot) {
      return false;
    }

    if (inst.arch_name == remill::kArchInvalid) {
      inst.arch_name = preferred_arch;
    }

    if (inst.arch_name == remill::kArchAArch32LittleEndian) {
      return aarch32->DecodeInstruction(address, instr_bytes, inst);
    } else {
      return thumb2->DecodeInstruction(address, instr_bytes, inst);
    }
  }

  // Minimum alignment of an instruction for this particular architecture.
  uint64_t MinInstructionAlign(void) const final {
    return std::min(aarch32->MinInstructionAlign(),
                    thumb2->MinInstructionAlign());
  }

  // Minimum number of bytes in an instruction for this particular architecture.
  uint64_t MinInstructionSize(void) const final {
    return std::min(aarch32->MinInstructionSize(),
                    thumb2->MinInstructionSize());
  }

  // Maximum number of bytes in an instruction for this particular architecture.
  //
  // `permit_fuse_idioms` is `true` if Remill is allowed to decode multiple
  // instructions at a time and look for instruction fusing idioms that are
  // common to this architecture.
  uint64_t MaxInstructionSize(bool permit_fuse_idioms) const final {
    return std::max(aarch32->MaxInstructionSize(permit_fuse_idioms),
                    thumb2->MaxInstructionSize(permit_fuse_idioms));
  }

  // Default calling convention for this architecture.
  llvm::CallingConv::ID DefaultCallingConv(void) const final {
    return aarch32->DefaultCallingConv();
  }

  // Get the LLVM triple for this architecture.
  llvm::Triple Triple(void) const final {
    return aarch32->Triple();
  }

  // Get the LLVM DataLayout for this architecture.
  llvm::DataLayout DataLayout(void) const final {
    return aarch32->DataLayout();
  }

  // Returns `true` if memory access are little endian byte ordered.
  bool MemoryAccessIsLittleEndian(void) const final {
    return true;
  }

  // Returns `true` if a given instruction might have a delay slot.
  bool MayHaveDelaySlot(const remill::Instruction &) const final {
    return false;
  }

  // Returns `true` if we should lift the semantics of `next_inst` as a delay
  // slot of `inst`. The `branch_taken_path` tells us whether we are in the
  // context of the taken path of a branch or the not-taken path of a branch.
  bool NextInstructionIsDelayed(const remill::Instruction &,
                                const remill::Instruction &, bool) const final {
    return false;
  }

  // Populate the table of register information.
  void PopulateRegisterTable(void) const final {}

  // Populate a just-initialized lifted function function with architecture-
  // specific variables.
  void FinishLiftedFunctionInitialization(llvm::Module *module,
                                          llvm::Function *bb_func) const final {
    aarch32->FinishLiftedFunctionInitialization(module, bb_func);

    // NOTE(pag): The thumb2 SLEIGH arch uses the same state structure as
    //            the remill aarch32 code.
  }

  // Add a register into this architecture.
  //
  // NOTE(pag): Internal API; do not invoke unless you are proxying/composing
  //            architectures.
  const remill::Register *AddRegister(const char *name, llvm::Type *, size_t,
                                      const char *) const final {
    return aarch32->RegisterByName(name);
  }

  // Get the state pointer and various other types from the `llvm::LLVMContext`
  // associated with `module`.
  //
  // NOTE(pag): This is an internal API.
  void InitFromSemanticsModule(llvm::Module *module) const final {
    aarch32->InitFromSemanticsModule(module);
    thumb2->InitFromSemanticsModule(module);
  }

  // TODO(Ian): This is kinda messy but only an arch currently knows if it is sleigh or not and sleigh needs different lifting context etc
  remill::InstructionLifter::LifterPtr
  DefaultLifter(const remill::IntrinsicTable &intrinsics) const final {
    return std::unique_ptr<remill::InstructionLifter>(
        new AArch32InstructionLifter(this, intrinsics));
  }
};


AArch32InstructionLifter::AArch32InstructionLifter(
    const AArch32Arch *arch_, const remill::IntrinsicTable &intrinsics_)
    : remill::InstructionLifter(arch_, intrinsics_),
      aarch32(arch_->aarch32->DefaultLifter(intrinsics_)),
      thumb2(arch_->thumb2->DefaultLifter(intrinsics_)) {}

}  // namespace

remill::Arch::ArchPtr BuildArch(llvm::LLVMContext &context,
                                remill::ArchName arch_name,
                                remill::OSName os_name) {
  if (arch_name == remill::ArchName::kArchAArch32LittleEndian ||
      arch_name == remill::ArchName::kArchThumb2LittleEndian) {
    return std::make_unique<AArch32Arch>(&context, os_name, arch_name);
  } else {
    return remill::Arch::Build(&context, os_name, arch_name);
  }
}

}  // namespace anvill
