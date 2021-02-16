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

#pragma once

#include <llvm/IR/CallingConv.h>
#include <remill/BC/Compat/Error.h>

#include <string>
#include <vector>

namespace llvm {
class Function;
}  // namespace llvm
namespace remill {
class Arch;
enum ArchName : uint32_t;
class IntrinsicTable;
struct Register;
}  // namespace remill
namespace anvill {

struct FunctionDecl;
struct ValueDecl;
struct ParameterDecl;

enum SizeConstraint : unsigned {
  kBit8 = (1 << 0),
  kBit16 = (1 << 1),
  kBit32 = (1 << 2),
  kBit64 = (1 << 3),
  kBit80 = (1 << 4),
  kBit128 = (1 << 5),
  kBit256 = (1 << 6),
  kBit512 = (1 << 7),

  kMaxBit512 =
      kBit512 | kBit256 | kBit128 | kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit256 = kBit256 | kBit128 | kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit128 = kBit128 | kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit80 = kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit64 = kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit32 = kBit32 | kBit16 | kBit8,
  kMaxBit16 = kBit16 | kBit8,
  kMaxBit8 = kBit8,

  kMinBit512 = kBit512,
  kMinBit256 = kBit512 | kBit256,
  kMinBit128 = kBit512 | kBit256 | kBit128,
  kMinBit80 = kBit512 | kBit256 | kBit128 | kBit80,
  kMinBit64 = kBit512 | kBit256 | kBit128 | kBit80 | kBit64,
  kMinBit32 = kBit512 | kBit256 | kBit128 | kBit80 | kBit64 | kBit32,
  kMinBit16 = kBit512 | kBit256 | kBit128 | kBit80 | kBit64 | kBit32 | kBit16,
  kMinBit8 =
      kBit512 | kBit256 | kBit128 | kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
};

enum TypeConstraint : unsigned {
  kTypeInt = (1 << 0),
  kTypePtr = (1 << 1),
  kTypeFloat = (1 << 2),
  kTypeVec = (1 << 3),

  kTypeIntegral = kTypeInt | kTypePtr,
  kTypeNumeric = kTypeIntegral | kTypeFloat,
  kTypeFloatOrVec = kTypeFloat | kTypeVec,
};

// Captures the constraints of different register sizes
struct VariantConstraint {
  VariantConstraint(std::string _register_name, TypeConstraint _type_constraint,
                    SizeConstraint _size_constraint)
      : register_name(_register_name),
        type_constraint(_type_constraint),
        size_constraint(_size_constraint) {}

  std::string register_name;
  TypeConstraint type_constraint;
  SizeConstraint size_constraint;
};

// Captures the different sizes and constraints of a single register
struct RegisterConstraint {
  RegisterConstraint(std::vector<VariantConstraint> _variants)
      : variants(std::move(_variants)) {}

  std::vector<VariantConstraint> variants;

  bool ContainsVariant(const std::string &name) const;
};

struct SizeAndType {
  SizeAndType(SizeConstraint _sc, TypeConstraint _tc) : sc(_sc), tc(_tc) {}

  SizeConstraint sc;
  TypeConstraint tc;
};

std::vector<std::string> TryRecoverParamNames(const llvm::Function &function);

// Return a vector of register constraints, augmented to to support additional
// registers made available in AVX or AVX512.
std::vector<RegisterConstraint>
ApplyX86Ext(const std::vector<RegisterConstraint> &constraints,
            remill::ArchName arch_name);

// Select and return one of `basic`, `avx`, or `avx512` given `arch_name`.
const std::vector<RegisterConstraint> &
SelectX86Constraint(remill::ArchName arch_name,
                    const std::vector<RegisterConstraint> &basic,
                    const std::vector<RegisterConstraint> &avx,
                    const std::vector<RegisterConstraint> &avx512);

class CallingConvention {
 public:
  CallingConvention(llvm::CallingConv::ID _identity, const remill::Arch *_arch)
      : arch(_arch),
        identity(_identity) {}

  virtual ~CallingConvention(void) = default;

  static llvm::Expected<std::unique_ptr<CallingConvention>>
  CreateCCFromArch(const remill::Arch *arch);

  static llvm::Expected<std::unique_ptr<CallingConvention>>
  CreateCCFromCCID(const llvm::CallingConv::ID, const remill::Arch *arch);

  virtual llvm::Error AllocateSignature(FunctionDecl &fdecl,
                                        llvm::Function &func) = 0;

  llvm::CallingConv::ID getIdentity(void) const {
    return identity;
  }

 protected:
  const remill::Arch *const arch;

  static std::unique_ptr<CallingConvention>
  CreateX86_C(const remill::Arch *arch);

  static std::unique_ptr<CallingConvention>
  CreateX86_StdCall(const remill::Arch *arch);

  static std::unique_ptr<CallingConvention>
  CreateX86_FastCall(const remill::Arch *arch);

  static std::unique_ptr<CallingConvention>
  CreateX86_ThisCall(const remill::Arch *arch);

  static std::unique_ptr<CallingConvention>
  CreateX86_64_SysV(const remill::Arch *arch);

  static std::unique_ptr<CallingConvention>
  CreateAArch64_C(const remill::Arch *arch);

  static std::unique_ptr<CallingConvention>
  CreateSPARC32_C(const remill::Arch *arch);

  static std::unique_ptr<CallingConvention>
  CreateSPARC64_C(const remill::Arch *arch);

 private:
  const llvm::CallingConv::ID identity;
};

}  // namespace anvill
