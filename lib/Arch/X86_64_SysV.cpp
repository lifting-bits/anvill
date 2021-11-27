/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Decls.h>
#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>

#include "AllocationState.h"
#include "Arch.h"

namespace anvill {
namespace {

static const std::vector<RegisterConstraint> kParamRegConstraints = {
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
        VariantConstraint("R8B", kTypeIntegral, kMaxBit8),
        VariantConstraint("R8W", kTypeIntegral, kMaxBit16),
        VariantConstraint("R8D", kTypeIntegral, kMaxBit32),
        VariantConstraint("R8", kTypeIntegral, kMaxBit64),
    }),
    RegisterConstraint({
        VariantConstraint("R9B", kTypeIntegral, kMaxBit8),
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

static const std::vector<RegisterConstraint> kAVXParamRegConstraints =
    ApplyX86Ext(kParamRegConstraints, remill::kArchAMD64_AVX);

static const std::vector<RegisterConstraint> kAVX512ParamRegConstraints =
    ApplyX86Ext(kParamRegConstraints, remill::kArchAMD64_AVX512);

// This a bit undocumented and warrants and explanation. For x86_64, clang has
// the option to split a created (not passed by reference) struct over the
// following registers: RAX, RDX, RCX, XMM0, XMM1, ST0, ST1. The first 3 are
// used for integer or pointer types and the last 4 are used for floating
// point values. If there is no valid struct split using these registers then
// the compiler will try RVO.
static const std::vector<RegisterConstraint> kReturnRegConstraints = {
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

static const std::vector<RegisterConstraint> kAVXReturnRegConstraints =
    ApplyX86Ext(kReturnRegConstraints, remill::kArchAMD64_AVX);

static const std::vector<RegisterConstraint> kAVX512ReturnRegConstraints =
    ApplyX86Ext(kReturnRegConstraints, remill::kArchAMD64_AVX512);

}  // namespace

class X86_64_SysV : public CallingConvention {
 public:
  explicit X86_64_SysV(const remill::Arch *arch);
  virtual ~X86_64_SysV(void) = default;

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
CallingConvention::CreateX86_64_SysV(const remill::Arch *arch) {
  return std::unique_ptr<CallingConvention>(new X86_64_SysV(arch));
}

X86_64_SysV::X86_64_SysV(const remill::Arch *arch)
    : CallingConvention(llvm::CallingConv::X86_64_SysV, arch),
      parameter_register_constraints(SelectX86Constraint(
          arch->arch_name, kParamRegConstraints, kAVXParamRegConstraints,
          kAVX512ParamRegConstraints)),
      return_register_constraints(SelectX86Constraint(
          arch->arch_name, kReturnRegConstraints, kAVXReturnRegConstraints,
          kAVX512ReturnRegConstraints)) {}

// Allocates the elements of the function signature of func to memory or
// registers. This includes parameters/arguments, return values, and the return
// stack pointer.
llvm::Error X86_64_SysV::AllocateSignature(FunctionDecl &fdecl,
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

  // For the X86_64_SysV ABI, it is always:
  //
  // "return_stack_pointer": {
  //     "offset": "8",
  //     "register": "RSP",
  //     "type": "L"
  // }

  fdecl.return_stack_pointer_offset = 8;
  fdecl.return_stack_pointer = arch->RegisterByName("RSP");

  fdecl.return_address.mem_reg = fdecl.return_stack_pointer;
  fdecl.return_address.mem_offset = 0;
  fdecl.return_address.type = fdecl.return_stack_pointer->type;

  return llvm::Error::success();
}

llvm::Error
X86_64_SysV::BindReturnValues(llvm::Function &function, bool &injected_sret,
                              std::vector<anvill::ValueDecl> &ret_values) {

  llvm::Type *ret_type = function.getReturnType();
  injected_sret = false;

  // If there is an sret parameter then it is a special case. For the
  // X86_64_SysV ABI, the sret parameters are guarenteed the be in %rax. In this
  // case, we can assume the actual return value of the function will be the
  // sret struct pointer.
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

    value_declaration.reg = arch->RegisterByName("RAX");
    return llvm::Error::success();
  }

  switch (ret_type->getTypeID()) {
    case llvm::Type::VoidTyID: return llvm::Error::success();

    case llvm::Type::IntegerTyID: {
      const auto *int_ty = llvm::dyn_cast<llvm::IntegerType>(ret_type);
      const auto int64_ty = llvm::Type::getInt64Ty(int_ty->getContext());
      const auto bit_width = int_ty->getBitWidth();

      // Put into RAX.
      if (bit_width <= 64) {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName("RAX");
        value_declaration.type = ret_type;
        return llvm::Error::success();

      // Split over RDX:RAX
      } else if (bit_width <= 128) {
        auto &v0 = ret_values.emplace_back();
        v0.reg = arch->RegisterByName("RAX");
        v0.type = int64_ty;

        auto &v1 = ret_values.emplace_back();
        v1.reg = arch->RegisterByName("RDX");
        v1.type = int64_ty;

        return llvm::Error::success();

      // Split over RCX:RDX:RAX.
      } else if (bit_width <= 192) {
        auto &v0 = ret_values.emplace_back();
        v0.reg = arch->RegisterByName("RAX");
        v0.type = int64_ty;

        auto &v1 = ret_values.emplace_back();
        v1.reg = arch->RegisterByName("RDX");
        v1.type = int64_ty;

        auto &v2 = ret_values.emplace_back();
        v2.reg = arch->RegisterByName("RCX");
        v2.type = int64_ty;

        return llvm::Error::success();

      // Otherwise, try to do a regular allocation for big integers.
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

    // Pointers always fit into `RAX`.
    case llvm::Type::PointerTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("RAX");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    // Floats and doubles always go in `xmm0`.
    case llvm::Type::FloatTyID:
    case llvm::Type::DoubleTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("XMM0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::X86_MMXTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("MM0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::X86_FP80TyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("ST0");
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
        value_declaration.reg = arch->RegisterByName("RAX");
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

// For X86_64_SysV, the general argument passing behavior is, try to pass the
// arguments in registers RDI, RSI, RDX, RCX, R8, R9 from integral types and
// XMM0 - XMM7 for float types. If the argument is a struct but can be
// completely split over the above registers, then greedily split it over the
// registers. Otherwise, the struct is passed entirely on the stack. If we run
// our of registers then pass the rest of the arguments on the stack.
llvm::Error X86_64_SysV::BindParameters(
    llvm::Function &function, bool injected_sret,
    std::vector<ParameterDecl> &parameter_declarations) {

  const auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // Used to keep track of which registers have been allocated
  AllocationState alloc_param(parameter_register_constraints, arch, this);

  // Stack offset describes the stack position of the first stack argument on
  // entry to the callee. For X86_64_SysV, this is [rsp + 8] since there is the
  // return address at [rsp].
  uint64_t stack_offset = 8;

  // If there is an injected sret (an implicit sret) then we need to allocate
  // the first parameter to the sret struct. The type of said sret parameter
  // will be the return type of the function.
  if (injected_sret) {
    auto &decl = parameter_declarations.emplace_back();

    decl.name = "__struct_ret_ptr";
    decl.type = function.getReturnType();
    decl.reg = arch->RegisterByName("RAX");
    alloc_param.reserved[0] = true;
  }

  const auto rsp_reg = arch->RegisterByName("RSP");

  for (auto &argument : function.args()) {
    const auto &param_name = param_names[argument.getArgNo()];
    const auto param_type = argument.getType();

    // Try to allocate from a register. If a register is not available then
    // allocate from the stack.
    if (auto allocation = alloc_param.TryRegisterAllocate(*param_type)) {
      auto prev_size = parameter_declarations.size();

      for (const auto &param_decl : allocation.getValue()) {
        auto &declaration = parameter_declarations.emplace_back();
        declaration.type = param_decl.type;
        if (param_decl.reg) {
          declaration.reg = param_decl.reg;
        } else {
          declaration.mem_offset = param_decl.mem_offset;
          declaration.mem_reg = param_decl.mem_reg;
        }
      }

      // The parameter fit in one register / stack slot.
      if ((prev_size + 1u) == parameter_declarations.size()) {
        if (!param_name.empty()) {
          parameter_declarations[prev_size].name = param_name;
        }

      // The parameter was spread across multiple registers.
      } else if (!param_name.empty()) {
        for (auto i = 0u; i < (parameter_declarations.size() - prev_size);
             ++i) {
          parameter_declarations[prev_size + i].name =
              param_name + std::to_string(i);
        }
      }

    } else {
      auto &declaration = parameter_declarations.emplace_back();
      declaration.type = param_type;
      declaration.mem_offset = static_cast<int64_t>(stack_offset);
      declaration.mem_reg = rsp_reg;
      stack_offset += dl.getTypeAllocSize(argument.getType());

      if (!param_name.empty()) {
        declaration.name = param_name;
      }
    }
  }

  return llvm::Error::success();
}

}  // namespace anvill
