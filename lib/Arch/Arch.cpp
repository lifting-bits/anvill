/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Arch.h"

#include <anvill/Decl.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

namespace remill {
class Arch;
class IntrinsicTable;
struct Register;
}  // namespace remill

namespace anvill {

// Return true if the RegisterConstraint contains the named variant.
bool RegisterConstraint::ContainsVariant(const std::string &name) const {
  for (const auto &v : variants) {
    if (v.register_name == name) {
      return true;
    }
  }
  return false;
}

llvm::Expected<std::unique_ptr<CallingConvention>>
CallingConvention::CreateCCFromArch(const remill::Arch *arch) {
  switch (arch->arch_name) {
    case remill::kArchInvalid:
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Invalid architecture");

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

    case remill::kArchAArch64LittleEndian:
      return CreateAArch64_C(arch);

    // Fallthrough for unsupported architectures
    default: break;
  }

  const auto arch_name = remill::GetArchName(arch->arch_name);
  const auto os_name = remill::GetOSName(arch->os_name);
  return llvm::createStringError(
      std::make_error_code(std::errc::invalid_argument),
      "Unsupported architecture/OS pair: %s and %s", arch_name.c_str(),
      os_name.c_str());
}

// Still need the arch to be passed in so we can create the calling convention
llvm::Expected<std::unique_ptr<CallingConvention>>
CallingConvention::CreateCCFromCCID(const llvm::CallingConv::ID cc_id,
                                    const remill::Arch *arch) {
  switch (cc_id) {
    case llvm::CallingConv::C:
      if (arch->IsX86()) {
        return CreateX86_C(arch);
      } else if (arch->IsAMD64()) {
        return CreateX86_64_SysV(arch);
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

  return llvm::createStringError(
      std::make_error_code(std::errc::invalid_argument),
      "Unsupported calling convention ID %u", static_cast<unsigned>(cc_id));
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

      // Assuming the name of the register is of the form XMM_
      const auto reg_number =
          std::to_string(c.variants.front().register_name.back());
      if (is_avx) {
        ret.push_back(RegisterConstraint({
            VariantConstraint("XMM" + reg_number, kTypeFloatOrVec, kMaxBit128),
            VariantConstraint("YMM" + reg_number, kTypeFloatOrVec, kMaxBit256),
        }));

      } else if (is_avx512) {
        ret.push_back(RegisterConstraint({
            VariantConstraint("XMM" + reg_number, kTypeFloatOrVec, kMaxBit128),
            VariantConstraint("YMM" + reg_number, kTypeFloatOrVec, kMaxBit256),
            VariantConstraint("ZMM" + reg_number, kTypeFloatOrVec, kMaxBit512),
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
