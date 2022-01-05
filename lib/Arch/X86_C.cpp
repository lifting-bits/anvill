/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Declarations.h>
#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>

#include "AllocationState.h"
#include "Arch.h"

namespace anvill {
namespace {

// Register based parameter passing is generally not allowed for x86_C for
// types other than vector types. Even in the case of vector types it is
// important to note that if LLVM lowers something like a vector(2) of floats
// to <float, float> in IR, we will not be able to allocate it to a vector
// register because in our eyes it will no longer be a vector. This is
// consistent with the behavior of Clang but not GCC.
static const std::vector<RegisterConstraint> kParamRegConstraints = {
    RegisterConstraint({VariantConstraint("XMM0", kTypeVec, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("XMM1", kTypeVec, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("XMM2", kTypeVec, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("XMM3", kTypeVec, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("XMM4", kTypeVec, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("XMM5", kTypeVec, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("XMM6", kTypeVec, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("XMM7", kTypeVec, kMaxBit128)}),
};

static const std::vector<RegisterConstraint> kAVXParamRegConstraints =
    ApplyX86Ext(kParamRegConstraints, remill::kArchAMD64_AVX);

static const std::vector<RegisterConstraint> kAVX512ParamRegConstraints =
    ApplyX86Ext(kParamRegConstraints, remill::kArchAMD64_AVX512);

// For x86_C (cdecl), structs can be split over EAX, EDX, ECX, ST0, ST1.
static const std::vector<RegisterConstraint> kReturnRegConstraints = {
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

static const std::vector<RegisterConstraint> kAVXReturnRegConstraints =
    ApplyX86Ext(kReturnRegConstraints, remill::kArchAMD64_AVX);

static const std::vector<RegisterConstraint> kAVX512ReturnRegConstraints =
    ApplyX86Ext(kReturnRegConstraints, remill::kArchAMD64_AVX512);

}  // namespace

// This is the cdecl calling convention referenced by llvm::CallingConv::C
class X86_C : public CallingConvention {
 public:
  explicit X86_C(const remill::Arch *arch);
  virtual ~X86_C(void) = default;

  llvm::Error AllocateSignature(FunctionDecl &fdecl,
                                llvm::Function &func) override;

 private:
  llvm::Error BindParameters(llvm::Function &function, bool injected_sret,
                             std::vector<ParameterDecl> &param_decls);

  llvm::Error BindReturnValues(llvm::Function &function, bool &injected_sret,
                               std::vector<ValueDecl> &ret_decls);

  const std::vector<RegisterConstraint> &parameter_register_constraints;
  const std::vector<RegisterConstraint> &return_register_constraints;
};

std::unique_ptr<CallingConvention>
CallingConvention::CreateX86_C(const remill::Arch *arch) {
  return std::unique_ptr<CallingConvention>(new X86_C(arch));
}

X86_C::X86_C(const remill::Arch *arch)
    : CallingConvention(llvm::CallingConv::C, arch),
      parameter_register_constraints(SelectX86Constraint(
          arch->arch_name, kParamRegConstraints, kAVXParamRegConstraints,
          kAVX512ParamRegConstraints)),
      return_register_constraints(SelectX86Constraint(
          arch->arch_name, kReturnRegConstraints, kAVXReturnRegConstraints,
          kAVX512ReturnRegConstraints)) {}

// Allocates the elements of the function signature of func to memory or
// registers. This includes parameters/arguments, return values, and the return
// stack pointer.
llvm::Error X86_C::AllocateSignature(FunctionDecl &fdecl,
                                     llvm::Function &func) {

  // Bind return values first to see if we have injected an sret into the
  // parameter list. Then, bind the parameters. It is important that we bind the
  // return values before the parameters in case we inject an sret.
  bool injected_sret = false;
  auto err = BindReturnValues(func, injected_sret, fdecl.returns);
  if (remill::IsError(err)) {
    return err;
  }

  err = BindParameters(func, injected_sret, fdecl.params);
  if (remill::IsError(err)) {
    return err;
  }

  // Check if the first argument is an sret. If it is, then by the X86_C ABI,
  // the callee is responbile for returning said sret argument in %eax and
  // cleaning up the sret argument with a `ret 4`. This changes the
  // return_stack_pointer offset because it will now be 4 bytes higher than we
  // thought.
  //
  // However, even if there is sret on the second argument as well, we do not
  // need to worry about this. For some reason the callee is only responsible
  // for cleaning up the case where an sret argument is passed in as the first
  // argument.
  if (func.hasParamAttribute(0, llvm::Attribute::StructRet) || injected_sret) {
    fdecl.return_stack_pointer_offset = 8;
  } else {
    fdecl.return_stack_pointer_offset = 4;
  }

  fdecl.return_stack_pointer = arch->RegisterByName("ESP");

  fdecl.return_address.mem_reg = fdecl.return_stack_pointer;
  fdecl.return_address.mem_offset = 0;
  fdecl.return_address.type = fdecl.return_stack_pointer->type;

  return llvm::Error::success();
}

llvm::Error
X86_C::BindReturnValues(llvm::Function &function, bool &injected_sret,
                        std::vector<anvill::ValueDecl> &ret_values) {

  llvm::Type *ret_type = function.getReturnType();
  injected_sret = false;

  // If there is an sret parameter then it is a special case. For the X86_C ABI,
  // the sret parameters are guarenteed the be in %eax. In this case, we can
  // assume the actual return value of the function will be the sret struct
  // pointer.
  if (function.hasStructRetAttr()) {
    auto &value_declaration = ret_values.emplace_back();

    // Check both first and second parameter because llvm does that in
    // llvm::Function::hasStructRetAttr()
    if (function.hasParamAttribute(0, llvm::Attribute::StructRet)) {
      value_declaration.type =
          remill::NthArgument(&function, 0)->getType()->getPointerElementType();

    } else if (function.hasParamAttribute(1, llvm::Attribute::StructRet)) {
      value_declaration.type =
          remill::NthArgument(&function, 1)->getType()->getPointerElementType();
    }

    value_declaration.type = llvm::PointerType::get(value_declaration.type, 0);

    if (!ret_type->isVoidTy()) {
      return llvm::createStringError(
          std::errc::invalid_argument,
          "Function '%s' with sret-attributed parameter has non-void return type '%s'",
          function.getName().str().c_str(),
          remill::LLVMThingToString(ret_type).c_str());
    }

    value_declaration.reg = arch->RegisterByName("EAX");
    return llvm::Error::success();
  }


  switch (ret_type->getTypeID()) {
    case llvm::Type::VoidTyID: return llvm::Error::success();

    case llvm::Type::IntegerTyID: {
      const auto *int_ty = llvm::dyn_cast<llvm::IntegerType>(ret_type);
      const auto int32_ty = llvm::Type::getInt32Ty(int_ty->getContext());
      const auto bit_width = int_ty->getBitWidth();

      // Put into EAX.
      if (bit_width <= 32) {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName("EAX");
        value_declaration.type = ret_type;
        return llvm::Error::success();

      // Put into EDX:EAX.
      } else if (bit_width <= 64) {
        auto &v0 = ret_values.emplace_back();
        v0.reg = arch->RegisterByName("EAX");
        v0.type = int32_ty;

        auto &v1 = ret_values.emplace_back();
        v1.reg = arch->RegisterByName("EDX");
        v1.type = int32_ty;
        return llvm::Error::success();

      // Split over ECX:EDX:EAX
      } else if (bit_width <= 96) {
        auto &v0 = ret_values.emplace_back();
        v0.reg = arch->RegisterByName("EAX");
        v0.type = int32_ty;

        auto &v1 = ret_values.emplace_back();
        v1.reg = arch->RegisterByName("EDX");
        v1.type = int32_ty;

        auto &v2 = ret_values.emplace_back();
        v2.reg = arch->RegisterByName("ECX");
        v2.type = int32_ty;
        return llvm::Error::success();

      } else {
        AllocationState alloc_ret(return_register_constraints, arch, this);
        auto mapping = alloc_ret.TryRegisterAllocate(*ret_type);
        if (mapping) {
          mapping.getValue().swap(ret_values);
          return llvm::Error::success();

        } else {
          return llvm::createStringError(
              std::errc::invalid_argument,
              "Could not allocate integral type '%s' to return register in function '%s'",
              remill::LLVMThingToString(ret_type).c_str(),
              function.getName().str().c_str());
        }
      }
    }

    // Pointers always fit into `EAX`.
    case llvm::Type::PointerTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("EAX");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    // Allocate ST0 for a floating point values.
    case llvm::Type::FloatTyID:
    case llvm::Type::DoubleTyID:
    case llvm::Type::X86_FP80TyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("ST0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::X86_MMXTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("MM0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    // Try to split the composite type over registers, and fall back on RVO
    // if it's not possible.
    case llvm::GetFixedVectorTypeId():
    case llvm::Type::ArrayTyID:
    case llvm::Type::StructTyID: {
      AllocationState alloc_ret(return_register_constraints, arch, this);
      auto mapping = alloc_ret.TryRegisterAllocate(*ret_type);

      // There is a valid split over registers, so add the mapping
      if (mapping) {
        return alloc_ret.CoalescePacking(mapping.getValue(), ret_values);

      // Composite type splitting didn't work so do RVO. Assume that the
      // pointer to the return value resides in RAX.
      } else {
        injected_sret = true;

        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName("EAX");
        value_declaration.type = llvm::PointerType::get(ret_type, 0);
        return llvm::Error::success();
      }
    }

    default:
      return llvm::createStringError(
          std::errc::invalid_argument,
          "Could not allocate unsupported type '%s' to return register in function '%s'",
          remill::LLVMThingToString(ret_type).c_str(),
          function.getName().str().c_str());
  }
}

llvm::Error
X86_C::BindParameters(llvm::Function &function, bool injected_sret,
                      std::vector<ParameterDecl> &parameter_declarations) {

  auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // stack_offset describes the position of the first stack argument on entry to
  // the callee. For X86_C, this is at [esp + 4] because the return address is
  // pushed onto the stack upon call instruction at [esp].
  uint64_t stack_offset = 4;

  const auto esp_reg = arch->RegisterByName("ESP");

  // If there is an injected sret (an implicit sret) then we need to allocate
  // the first parameter to the sret struct. The type of said sret parameter
  // will be the return type of the function.
  if (injected_sret) {
    auto &decl = parameter_declarations.emplace_back();

    decl.type = function.getReturnType();
    decl.mem_offset = static_cast<int64_t>(stack_offset);
    decl.mem_reg = esp_reg;
    stack_offset += dl.getTypeAllocSize(decl.type);
  }

  for (auto &argument : function.args()) {
    auto &declaration = parameter_declarations.emplace_back();

    declaration.type = argument.getType();

    // Since there are no registers, just allocate from the stack
    declaration.mem_offset = static_cast<int64_t>(stack_offset);
    declaration.mem_reg = esp_reg;
    stack_offset += dl.getTypeAllocSize(argument.getType());

    // Get a name for the IR parameter.
    // Need to add 1 because param_names uses logical numbering, but
    // argument.getArgNo() uses index numbering.
    declaration.name = param_names[argument.getArgNo()];
  }

  return llvm::Error::success();
}

}  // namespace anvill
