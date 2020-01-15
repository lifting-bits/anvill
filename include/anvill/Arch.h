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

#include "Decl.h"

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
};

enum TypeConstraint : unsigned {
  kTypeInt = (1 << 0),
  kTypePtr = (1 << 1),
  kTypeFloat = (1 << 2),
  kTypeVec = (1 << 3),

  kTypeIntegral = kTypeInt | kTypePtr,
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
      : variants(_variants) {}

  std::vector<VariantConstraint> variants;
};

class CallingConvention {
 public:
  CallingConvention(llvm::CallingConv::ID _identity, const remill::Arch *_arch) : arch(_arch), identity(_identity) {}
  virtual ~CallingConvention() = default;

  virtual std::vector<ParameterDecl> BindParameters(
      const llvm::Function &function) = 0;
  virtual std::vector<ValueDecl> BindReturnValues(
      const llvm::Function &function) = 0;
  virtual void BindReturnStackPointer(FunctionDecl &fdecl,
                                       const llvm::Function &func) = 0;

  llvm::CallingConv::ID getIdentity() { return identity; }

  // Try to allocate a register for the argument based on the register constraints
  // and what has already been reserved. Return nullptr if there is no possible
  // register allocation.
  const remill::Register *TryRegisterAllocate(
    llvm::Type &type, std::vector<bool> &reserved,
    const std::vector<RegisterConstraint> &register_constraints);

  // For each element of the struct, try to allocate it to a register, if all of
  // them can be allocated, then return that allocation. Otherwise return a
  // nullptr.
  std::unique_ptr<std::vector<anvill::ValueDecl>> TryReturnThroughRegisters(
      const llvm::StructType &st,
      const std::vector<RegisterConstraint> &constraints);

  const remill::Arch* arch;

 private:
  llvm::CallingConv::ID identity;
};

class X86_64_SysV : public CallingConvention {
 public:
  X86_64_SysV(const remill::Arch *arch) : CallingConvention(llvm::CallingConv::X86_64_SysV, arch) {}
  virtual ~X86_64_SysV() = default;
  std::vector<ParameterDecl> BindParameters(const llvm::Function &function);
  std::vector<ValueDecl> BindReturnValues(const llvm::Function &function);
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

      RegisterConstraint({VariantConstraint("XMM0", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM1", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM2", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM3", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM4", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM5", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM6", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM7", kTypeFloat, kMaxBit128)}),
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
      RegisterConstraint({VariantConstraint("XMM0", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM1", kTypeFloat, kMaxBit128)}),

      // Since the FPU registers are 80 bits wide, they are only able to hold
      // 64-bit values.
      RegisterConstraint({VariantConstraint("ST0", kTypeFloat, kMaxBit80)}),
      RegisterConstraint({VariantConstraint("ST1", kTypeFloat, kMaxBit80)}),
  };
};

// This is the cdecl calling convention referenced by llvm::CallingConv::C
class X86_C : public CallingConvention {
 public:
  X86_C(remill::Arch *arch) : CallingConvention(llvm::CallingConv::C, arch) {}
  virtual ~X86_C() = default;
  std::vector<ParameterDecl> BindParameters(const llvm::Function &function);
  std::vector<ValueDecl> BindReturnValues(const llvm::Function &function);
  void BindReturnStackPointer(FunctionDecl &fdecl, const llvm::Function &func);

 private:
  // Register allocations for parameters are not allowed in vanilla cdecl
  const std::vector<RegisterConstraint> parameter_register_constraints = {};

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
      RegisterConstraint({VariantConstraint("ST0", kTypeFloat, kMaxBit80)}),
      RegisterConstraint({VariantConstraint("ST1", kTypeFloat, kMaxBit80)}),
  };
};

}  // namespace anvill