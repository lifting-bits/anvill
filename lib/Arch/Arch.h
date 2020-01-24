#pragma once

#include <string>
#include <vector>

#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "anvill/Decl.h"

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

  kMaxBit128 = kBit128 | kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit80 = kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit64 = kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit32 = kBit32 | kBit16 | kBit8,
  kMaxBit16 = kBit16 | kBit8,
  kMaxBit8 = kBit8,

  kMinBit128 = kBit128,
  kMinBit80 = kBit128 | kBit80,
  kMinBit64 = kBit128 | kBit80 | kBit64,
  kMinBit32 = kBit128 | kBit80 | kBit64 | kBit32,
  kMinBit16 = kBit128 | kBit80 | kBit64 | kBit32 | kBit16,
  kMinBit8 = kBit128 | kBit80 | kBit64 | kBit32 | kBit16 | kBit8,
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
};

std::map<unsigned, std::string> TryRecoverParamNames(
    const llvm::Function &function);

class CallingConvention {
 public:
  CallingConvention(llvm::CallingConv::ID _identity, const remill::Arch *_arch)
      : arch(_arch), identity(_identity) {}
  virtual ~CallingConvention() = default;

  virtual void AllocateSignature(FunctionDecl &fdecl,
                                 const llvm::Function &func) = 0;
  llvm::CallingConv::ID getIdentity() { return identity; }

 protected:
  // Try to allocate a register for the argument based on the register
  // constraints and what has already been reserved. Return nullptr if there is
  // no possible register allocation.
  const remill::Register *TryRegisterAllocate(
      llvm::Type &type, std::vector<bool> &reserved,
      const std::vector<RegisterConstraint> &register_constraints);

  // For each element of the struct, try to allocate it to a register, if all of
  // them can be allocated, then return that allocation. Otherwise return a
  // nullptr.
  std::unique_ptr<std::vector<anvill::ValueDecl>> TryReturnThroughRegisters(
      const llvm::StructType &st,
      const std::vector<RegisterConstraint> &constraints);

  const remill::Arch *arch;

 private:
  llvm::CallingConv::ID identity;

  std::unique_ptr<std::vector<anvill::ValueDecl>> TryReturnThroughRegistersInternal(
      const llvm::StructType &st,
      std::vector<bool> &reserved,
      const std::vector<RegisterConstraint> &constraints);
};

class X86_64_SysV : public CallingConvention {
 public:
  X86_64_SysV(const remill::Arch *arch)
      : CallingConvention(llvm::CallingConv::X86_64_SysV, arch) {}
  virtual ~X86_64_SysV() = default;
  void AllocateSignature(FunctionDecl &fdecl, const llvm::Function &func);
  std::vector<ParameterDecl> BindParameters(const llvm::Function &function,
                                            bool injected_sret);
  std::vector<ValueDecl> BindReturnValues(const llvm::Function &function,
                                          bool &injected_sret);
  void BindReturnStackPointer(FunctionDecl &fdecl, const llvm::Function &func);

 private:
  const std::vector<RegisterConstraint> parameter_register_constraints = {
      RegisterConstraint({
          VariantConstraint("DIL", kTypeIntegral, kMaxBit8),
          VariantConstraint("DI", kTypeIntegral, kMaxBit16),
          VariantConstraint("EDI", kTypeIntegral, kMaxBit32),
          VariantConstraint("RDI", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("SIL", kTypeIntegral, kMaxBit8),
          VariantConstraint("SI", kTypeIntegral, kMaxBit16),
          VariantConstraint("ESI", kTypeIntegral, kMaxBit32),
          VariantConstraint("RSI", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("DL", kTypeIntegral, kMaxBit8),
          VariantConstraint("DX", kTypeIntegral, kMaxBit16),
          VariantConstraint("EDX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RDX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("CL", kTypeIntegral, kMaxBit8),
          VariantConstraint("CX", kTypeIntegral, kMaxBit16),
          VariantConstraint("ECX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RCX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("R8L", kTypeIntegral, kMaxBit8),
          VariantConstraint("R8W", kTypeIntegral, kMaxBit16),
          VariantConstraint("R8D", kTypeIntegral, kMaxBit32),
          VariantConstraint("R8", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("R9L", kTypeIntegral, kMaxBit8),
          VariantConstraint("R9W", kTypeIntegral, kMaxBit16),
          VariantConstraint("R9D", kTypeIntegral, kMaxBit32),
          VariantConstraint("R9", kTypeIntegral, kMaxBit64),
      }),

      RegisterConstraint(
          {VariantConstraint("XMM0", kTypeFloatOrVec, kMaxBit128)}),
      RegisterConstraint(
          {VariantConstraint("XMM1", kTypeFloatOrVec, kMaxBit128)}),
      RegisterConstraint(
          {VariantConstraint("XMM2", kTypeFloatOrVec, kMaxBit128)}),
      RegisterConstraint(
          {VariantConstraint("XMM3", kTypeFloatOrVec, kMaxBit128)}),
      RegisterConstraint(
          {VariantConstraint("XMM4", kTypeFloatOrVec, kMaxBit128)}),
      RegisterConstraint(
          {VariantConstraint("XMM5", kTypeFloatOrVec, kMaxBit128)}),
      RegisterConstraint(
          {VariantConstraint("XMM6", kTypeFloatOrVec, kMaxBit128)}),
      RegisterConstraint(
          {VariantConstraint("XMM7", kTypeFloatOrVec, kMaxBit128)}),
  };

  // This a bit undocumented and warrants and explanation. For x86_64, clang has
  // the option to split a created (not passed by reference) struct over the
  // following registers: RAX, RDX, RCX, XMM0, XMM1, ST0, ST1. The first 3 are
  // used for integer or pointer types and the last 4 are used for floating
  // point values. If there is no valid struct split using these registers then
  // the compiler will try RVO.
  const std::vector<RegisterConstraint> return_register_constraints = {
      RegisterConstraint({
          VariantConstraint("AL", kTypeIntegral, kMaxBit8),
          VariantConstraint("AX", kTypeIntegral, kMaxBit16),
          VariantConstraint("EAX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RAX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("DL", kTypeIntegral, kMaxBit8),
          VariantConstraint("DX", kTypeIntegral, kMaxBit16),
          VariantConstraint("EDX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RDX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("CL", kTypeIntegral, kMaxBit8),
          VariantConstraint("CX", kTypeIntegral, kMaxBit16),
          VariantConstraint("ECX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RCX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({VariantConstraint("XMM0", kTypeVec, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM1", kTypeVec, kMaxBit128)}),

      // Since the FPU registers are 80 bits wide, they are only able to hold
      // 64-bit values.
      RegisterConstraint({VariantConstraint("ST0", kTypeVec, kMaxBit80)}),
      RegisterConstraint({VariantConstraint("ST1", kTypeVec, kMaxBit80)}),
  };
};

// This is the cdecl calling convention referenced by llvm::CallingConv::C
class X86_C : public CallingConvention {
 public:
  X86_C(const remill::Arch *arch)
      : CallingConvention(llvm::CallingConv::C, arch) {}
  virtual ~X86_C() = default;
  void AllocateSignature(FunctionDecl &fdecl, const llvm::Function &func);
  std::vector<ParameterDecl> BindParameters(const llvm::Function &function,
                                            bool injected_sret);
  std::vector<ValueDecl> BindReturnValues(const llvm::Function &function,
                                          bool &injected_sret);
  void BindReturnStackPointer(FunctionDecl &fdecl, const llvm::Function &func,
                              bool injected_sret);

 private:
  // Register based parameter passing is generally not allowed for x86_C for
  // types other than vector types. Even in the case of vector types it is
  // important to note that if LLVM lowers something like a vector(2) of floats
  // to <float, float> in IR, we will not be able to allocate it to a vector
  // register because in our eyes it will no longer be a vector. This is
  // consistent with the behavior of Clang but not GCC.
  const std::vector<RegisterConstraint> parameter_register_constraints = {
      RegisterConstraint({VariantConstraint("XMM0", kTypeVec, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM1", kTypeVec, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM2", kTypeVec, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM3", kTypeVec, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM4", kTypeVec, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM5", kTypeVec, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM6", kTypeVec, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM7", kTypeVec, kMaxBit128)}),
  };

  // For x86_C (cdecl), structs can be split over EAX, EDX, ECX, ST0, ST1.
  const std::vector<RegisterConstraint> return_register_constraints = {
      RegisterConstraint({
          VariantConstraint("AL", kTypeIntegral, kMaxBit8),
          VariantConstraint("AX", kTypeIntegral, kMaxBit16),
          VariantConstraint("EAX", kTypeIntegral, kMaxBit32),
      }),
      RegisterConstraint({
          VariantConstraint("DL", kTypeIntegral, kMaxBit8),
          VariantConstraint("DX", kTypeIntegral, kMaxBit16),
          VariantConstraint("EDX", kTypeIntegral, kMaxBit32),
      }),
      RegisterConstraint({
          VariantConstraint("CL", kTypeIntegral, kMaxBit8),
          VariantConstraint("CX", kTypeIntegral, kMaxBit16),
          VariantConstraint("ECX", kTypeIntegral, kMaxBit32),
      }),
      RegisterConstraint({VariantConstraint("ST0", kTypeVec, kMaxBit80)}),
      RegisterConstraint({VariantConstraint("ST1", kTypeVec, kMaxBit80)}),
  };
};

}  // namespace anvill