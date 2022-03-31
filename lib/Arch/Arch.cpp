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

  const auto is_avx =
      remill::kArchAMD64_AVX == arch_name || remill::kArchX86_AVX == arch_name;

  const auto is_avx512 = remill::kArchAMD64_AVX512 == arch_name ||
                         remill::kArchX86_AVX512 == arch_name;

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

}  // namespace anvill
