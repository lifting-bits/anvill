/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Specification.h>
#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>

#include "AllocationState.h"
#include "Arch.h"

namespace anvill {
namespace {

static const std::vector<RegisterConstraint> kParamRegConstraints = {
    RegisterConstraint({VariantConstraint("R0", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R1", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R2", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R3", kTypeIntegral, kMaxBit32)}),
};

static const std::vector<RegisterConstraint> kReturnRegConstraints = {
    RegisterConstraint({VariantConstraint("R0", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R1", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R2", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R3", kTypeIntegral, kMaxBit32)}),
};

// Used to split things like `i64`s into multiple `i32`s.
static llvm::Type *IntegerTypeSplitter(llvm::Type *type) {
  auto int_ty = llvm::dyn_cast<llvm::IntegerType>(type);
  if (!int_ty) {
    return nullptr;
  }

  auto width = int_ty->getPrimitiveSizeInBits();
  if (width <= 32) {
    return nullptr;
  }

  auto num_elements = (width + 31) / 32;
  auto i32_ty = llvm::Type::getInt32Ty(type->getContext());
  return llvm::ArrayType::get(i32_ty, num_elements);
}

}  // namespace

// This is AAPCS calling convention for armv7 architecture. It does not
// support AAPCS_VFP calling convention
// TODO(akshayk) Support AAPCS_VFP calling convention for VFP and advance
// SIMD support
class AArch32_C : public CallingConvention {
 public:
  explicit AArch32_C(const remill::Arch *arch);
  virtual ~AArch32_C(void) = default;

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
CallingConvention::CreateAArch32_C(const remill::Arch *arch) {
  return std::unique_ptr<CallingConvention>(new AArch32_C(arch));
}

AArch32_C::AArch32_C(const remill::Arch *arch)
    : CallingConvention(llvm::CallingConv::C, arch),
      parameter_register_constraints(kParamRegConstraints),
      return_register_constraints(kReturnRegConstraints) {}

// Allocates the elements of the function signature of func to memory or
// registers. This includes parameters/arguments, return values, and the return
// stack pointer.
llvm::Error AArch32_C::AllocateSignature(FunctionDecl &fdecl,
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

  fdecl.return_stack_pointer_offset = 0;
  fdecl.return_stack_pointer = arch->RegisterByName("SP");

  fdecl.return_address.reg = arch->RegisterByName("LR");
  fdecl.return_address.type = fdecl.return_address.reg->type;

  return llvm::Error::success();
}


llvm::Error
AArch32_C::BindReturnValues(llvm::Function &function, bool &injected_sret,
                            std::vector<anvill::ValueDecl> &ret_values) {

  llvm::Type *ret_type = function.getReturnType();
  injected_sret = false;

  // If there is an sret parameter then it is a special case.
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

    // Indirect return values are passed by pointer through `X8`.
    value_declaration.reg = arch->RegisterByName("R0");
    return llvm::Error::success();
  }

  switch (ret_type->getTypeID()) {
    case llvm::Type::VoidTyID: return llvm::Error::success();

    case llvm::Type::IntegerTyID: {
      const auto *int_ty = llvm::dyn_cast<llvm::IntegerType>(ret_type);
      const auto int32_ty = llvm::Type::getInt32Ty(int_ty->getContext());
      const auto bit_width = int_ty->getBitWidth();
      if (bit_width <= 32) {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName("R0");
        value_declaration.type = ret_type;
        return llvm::Error::success();

      } else if (bit_width <= 64) {
        const char *reg_names[] = {"R0", "R1"};
        for (auto i = 0u; i < 2 && (32 * i) < bit_width; ++i) {
          auto &value_declaration = ret_values.emplace_back();
          value_declaration.reg = arch->RegisterByName(reg_names[i]);
          value_declaration.type = int32_ty;
        }
        return llvm::Error::success();

      // Split the integer across `R3:R0`.
      } else if (bit_width <= 128) {
        const char *ret_names[] = {"R0", "R1", "R2", "R3"};
        for (auto i = 0u; i < 4 && (32 * i) < bit_width; ++i) {
          auto &value_declaration = ret_values.emplace_back();
          value_declaration.reg = arch->RegisterByName(ret_names[i]);
          value_declaration.type = int32_ty;
        }
        return llvm::Error::success();

      // The integer is too big to split across register;  fall back to
      // return-value optimization and pass it in R0
      } else {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.type =
            llvm::PointerType::get(value_declaration.type, 0);
        value_declaration.reg = arch->RegisterByName("R0");
        return llvm::Error::success();
      }
    }

    // Pointers always fit into `R0`.
    case llvm::Type::PointerTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("R0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::HalfTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("R0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::FloatTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("R0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::DoubleTyID: {

      // double types gets split into two integer registers
      const auto double_ty = llvm::Type::getDoubleTy(ret_type->getContext());

      // get the primitive type size to split them to registers
      const auto bit_width = double_ty->getScalarSizeInBits();
      const char *reg_names[] = {"R0", "R1"};
      for (auto i = 0u; i < 2 && (32 * i) < bit_width; ++i) {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName(reg_names[i]);
        value_declaration.type = double_ty;
      }
      return llvm::Error::success();
    }

    case llvm::Type::FP128TyID: {

      // double types gets split into two integer registers
      const auto fp128_ty = llvm::Type::getDoubleTy(ret_type->getContext());

      // get the primitive type size to split them to registers
      const auto bit_width = fp128_ty->getScalarSizeInBits();
      const char *reg_names[] = {"R0", "R1", "R2", "R3"};
      for (auto i = 0u; i < 2 && (32 * i) < bit_width; ++i) {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName(reg_names[i]);
        value_declaration.type = fp128_ty;
      }
      return llvm::Error::success();
    }

    // Try to split the composite type over registers, and fall back on RO
    // if it's not possible.
    case llvm::GetFixedVectorTypeId():
    case llvm::Type::ArrayTyID:
    case llvm::Type::StructTyID: {
      AllocationState alloc_ret(return_register_constraints, arch, this);
      alloc_ret.config.type_splitter = IntegerTypeSplitter;
      auto mapping = alloc_ret.TryRegisterAllocate(*ret_type);

      // There is a valid split over registers, so add the mapping
      if (mapping) {
        return alloc_ret.CoalescePacking(mapping.getValue(), ret_values);

      } else {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName("R0");
        value_declaration.type = llvm::PointerType::get(ret_type, 0);
        return llvm::Error::success();
      }
    }

    default: break;
  }

  return llvm::createStringError(
      std::errc::invalid_argument,
      "Could not allocate unsupported type '%s' to return register in function '%s'",
      remill::LLVMThingToString(ret_type).c_str(),
      function.getName().str().c_str());
}

llvm::Error
AArch32_C::BindParameters(llvm::Function &function, bool injected_sret,
                          std::vector<ParameterDecl> &parameter_declarations) {

  const auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // Used to keep track of which registers have been allocated
  AllocationState alloc_param(parameter_register_constraints, arch, this);
  alloc_param.config.type_splitter = IntegerTypeSplitter;

  //
  //  #define X unsigned int
  //  unsigned a(X a0, X a1, X a2, X a3,
  //             X a4, X a5, X a6) {
  //        return a6;
  //   }
  //   a:
  //     ldr     r0, [sp, #4]
  //     bx      lr
  //
  // In the example above argument a5 and a6 gets spilled over the stack
  // and gets access with the offset. stack offset for armv7 is 0

  unsigned stack_offset = 0;
  const auto sp_reg = arch->RegisterByName("SP");

  for (auto &argument : function.args()) {
    const auto &param_name = param_names[argument.getArgNo()];
    const auto param_type = argument.getType();

    auto allocation = alloc_param.TryRegisterAllocate(*param_type);

    // Try to allocate from a register. If a register is not available then
    // allocate from the stack.
    if (allocation) {
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
      declaration.mem_reg = sp_reg;
      stack_offset += dl.getTypeAllocSize(argument.getType());

      if (!param_name.empty()) {
        declaration.name = param_name;
      }
    }
  }

  return llvm::Error::success();
}

}  // namespace anvill
