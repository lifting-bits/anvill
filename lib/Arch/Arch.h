#pragma once

#include <string>
#include <vector>

#include <llvm/IR/CallingConv.h>

#include "anvill/Decl.h"

namespace llvm {

}  // namespace llvm
namespace remill {
class Arch;
class IntrinsicTable;
struct Register;
}  // namespace remill

namespace anvill {
enum SizeConstraint : unsigned {
  kBit8 = (1 << 0),
  kBit16 = (1 << 1),
  kBit32 = (1 << 2),
  kBit64 = (1 << 3),
  kBit80 = (1 << 4),
  kBit128 = (1 << 5),
  kBit256 = (1 << 6),
  kBit512 = (1 << 7),

  kMaxBit512 = kBit512 | kBit256 | kBit128 | kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
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
  kMinBit8 = kBit512 | kBit256 | kBit128 | kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
};

enum TypeConstraint : unsigned {
  kTypeInt = (1 << 0),
  kTypePtr = (1 << 1),
  kTypeFloat = (1 << 2),
  kTypeVec = (1 << 3),

  kTypeIntegral = kTypeInt | kTypePtr,
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
  SizeAndType(SizeConstraint _sc, TypeConstraint _tc)
      : sc(_sc),
        tc(_tc) {}

  SizeConstraint sc;
  TypeConstraint tc;
};

std::vector<std::string> TryRecoverParamNames(const llvm::Function &function);

// Return a vector of register constraints, augmented to to support additional
// registers made available in AVX or AVX512.
std::vector<RegisterConstraint> ApplyX86Ext(
    const std::vector<RegisterConstraint> &constraints,
    remill::ArchName arch_name);

// Select and return one of `basic`, `avx`, or `avx512` given `arch_name`.
const std::vector<RegisterConstraint> &SelectX86Constraint(
    remill::ArchName arch_name,
    const std::vector<RegisterConstraint> &basic,
    const std::vector<RegisterConstraint> &avx,
    const std::vector<RegisterConstraint> &avx512);

class CallingConvention {
 public:
  CallingConvention(llvm::CallingConv::ID _identity, const remill::Arch *_arch)
      : arch(_arch),
        identity(_identity) {}

  virtual ~CallingConvention(void) = default;

  static llvm::Expected<std::unique_ptr<CallingConvention>> CreateCCFromArch(
      const remill::Arch *arch);

  static llvm::Expected<std::unique_ptr<CallingConvention>> CreateCCFromCCID(
      const llvm::CallingConv::ID, const remill::Arch *arch);

  virtual llvm::Error AllocateSignature(FunctionDecl &fdecl,
                                        const llvm::Function &func) = 0;

  llvm::CallingConv::ID getIdentity(void) const {
    return identity;
  }

 protected:
  const remill::Arch *arch;

 private:
  llvm::CallingConv::ID identity;
};

class X86_64_SysV : public CallingConvention {
 public:
  explicit X86_64_SysV(const remill::Arch *arch);
  virtual ~X86_64_SysV(void) = default;

  llvm::Error AllocateSignature(FunctionDecl &fdecl,
                                const llvm::Function &func) override;

 private:
  llvm::Error BindParameters(const llvm::Function &function,
                             bool injected_sret,
                             std::vector<ParameterDecl> &param_decls);

  llvm::Error BindReturnValues(const llvm::Function &function,
                               bool &injected_sret,
                               std::vector<ValueDecl> &ret_decls);

  void BindReturnStackPointer(FunctionDecl &fdecl, const llvm::Function &func);

  const std::vector<RegisterConstraint> &parameter_register_constraints;
  const std::vector<RegisterConstraint> &return_register_constraints;
};

// This is the cdecl calling convention referenced by llvm::CallingConv::C
class X86_C : public CallingConvention {
 public:
  explicit X86_C(const remill::Arch *arch);
  virtual ~X86_C(void) = default;

  llvm::Error AllocateSignature(FunctionDecl &fdecl,
                                const llvm::Function &func) override;

 private:
  llvm::Error BindParameters(const llvm::Function &function, bool injected_sret,
                             std::vector<ParameterDecl> &param_decls);

  llvm::Error BindReturnValues(const llvm::Function &function,
                               bool &injected_sret,
                               std::vector<ValueDecl> &ret_decls);

  void BindReturnStackPointer(FunctionDecl &fdecl, const llvm::Function &func,
                              bool injected_sret);

  const std::vector<RegisterConstraint> &parameter_register_constraints;
  const std::vector<RegisterConstraint> &return_register_constraints;
};

}  // namespace anvill
