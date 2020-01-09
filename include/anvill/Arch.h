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
  kBit128 = (1 << 4),

  kMaxBit128 = kBit128 | kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit64 = kBit64 | kBit32 | kBit16 | kBit8,
  kMaxBit32 = kBit32 | kBit16 | kBit8,

  kMinBit128 = kBit128,
  kMinBit64 = kBit128 | kBit64,
  kMinBit32 = kBit128 | kBit64 | kBit32,
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
  CallingConvention(llvm::CallingConv::ID _identity) : identity(_identity) {}
  virtual ~CallingConvention(){};

  virtual std::vector<ParameterDecl> BindParameters(
      const llvm::Function &function) = 0;
  virtual std::vector<ValueDecl> BindReturnValues(
      const llvm::Function &function) = 0;
  virtual remill::Register *BindReturnStackPointer(
      const llvm::Function &function) = 0;

  llvm::CallingConv::ID getIdentity() { return identity; }

 private:
  llvm::CallingConv::ID identity;
};

class X86_64_SysV : public CallingConvention {
 public:
  X86_64_SysV() : CallingConvention(llvm::CallingConv::X86_64_SysV) {}
  ~X86_64_SysV(){};
  std::vector<ParameterDecl> BindParameters(const llvm::Function &function);
  std::vector<ValueDecl> BindReturnValues(const llvm::Function &function);
  remill::Register *BindReturnStackPointer(const llvm::Function &function);

 private:
  // TODO: add the rest of the Registers here, not just the 32-bit and 64-bit
  // variants
  const std::vector<RegisterConstraint> parameter_register_constraints = {
      RegisterConstraint({
          VariantConstraint("EDI", kTypeIntegral, kMaxBit32),
          VariantConstraint("RDI", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("ESI", kTypeIntegral, kMaxBit32),
          VariantConstraint("RSI", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("EDX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RDX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("ECX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RCX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("R8D", kTypeIntegral, kMaxBit32),
          VariantConstraint("R8", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
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
          VariantConstraint("EAX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RAX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("EDX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RDX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({
          VariantConstraint("ECX", kTypeIntegral, kMaxBit32),
          VariantConstraint("RCX", kTypeIntegral, kMaxBit64),
      }),
      RegisterConstraint({VariantConstraint("XMM0", kTypeFloat, kMaxBit128)}),
      RegisterConstraint({VariantConstraint("XMM1", kTypeFloat, kMaxBit128)}),

      // Since the FPU registers are 80 bits wide, they are only able to hold
      // 64-bit values.
      RegisterConstraint({VariantConstraint("ST0", kTypeFloat, kMaxBit64)}),
      RegisterConstraint({VariantConstraint("ST1", kTypeFloat, kMaxBit64)}),
  };
};

// This is the cdecl calling convention referenced by llvm::CallingConv::C
class X86_C : public CallingConvention {
 public:
  X86_C() : CallingConvention(llvm::CallingConv::C) {}
  ~X86_C() {};
  std::vector<ParameterDecl> BindParameters(const llvm::Function &function);
  std::vector<ValueDecl> BindReturnValues(const llvm::Function &function);
  remill::Register *BindReturnStackPointer(const llvm::Function &function);

 private:
  // Register allocations for parameters are not allowed in vanilla cdecl
  const std::vector<RegisterConstraint> parameter_register_constraints = {};

  // For x86_C (cdecl), structs can be split over EAX, EDX, ECX, ST0, ST1.
  const std::vector<RegisterConstraint> return_register_constraints = {
      RegisterConstraint({
          VariantConstraint("EAX", kTypeIntegral, kMaxBit32),
      }),
      RegisterConstraint({
          VariantConstraint("EDX", kTypeIntegral, kMaxBit32),
      }),
      RegisterConstraint({
          VariantConstraint("ECX", kTypeIntegral, kMaxBit32),
      }),
      RegisterConstraint({VariantConstraint("ST0", kTypeFloat, kMaxBit64)}),
      RegisterConstraint({VariantConstraint("ST1", kTypeFloat, kMaxBit64)}),
  };
};

// Try to allocate a register for the argument based on the register constraints
// and what has already been reserved. Return nullptr if there is no possible
// register allocation.
remill::Register *TryRegisterAllocate(
    const llvm::Argument &argument, std::vector<bool> &reserved,
    const std::vector<RegisterConstraint> &register_constraints);

std::string TranslateType(const llvm::Type &type);

}  // namespace anvill