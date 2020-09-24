/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <anvill/Decl.h>
#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>

#include "AllocationState.h"
#include "Arch.h"

namespace anvill {
namespace {

static const std::vector<RegisterConstraint> kParamRegConstraints = {
    RegisterConstraint({VariantConstraint("W0", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X0", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W1", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X1", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W2", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X2", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W3", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X3", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W4", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X4", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W5", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X5", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W6", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X6", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W7", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X7", kTypeIntegral, kMaxBit64)}),

    RegisterConstraint({VariantConstraint("H0", kTypeFloat, kMaxBit16),
                        VariantConstraint("S0", kTypeFloat, kMaxBit32),
                        VariantConstraint("D0", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H1", kTypeFloat, kMaxBit16),
                        VariantConstraint("S1", kTypeFloat, kMaxBit32),
                        VariantConstraint("D1", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H2", kTypeFloat, kMaxBit16),
                        VariantConstraint("S2", kTypeFloat, kMaxBit32),
                        VariantConstraint("D2", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H3", kTypeFloat, kMaxBit16),
                        VariantConstraint("S3", kTypeFloat, kMaxBit32),
                        VariantConstraint("D3", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H4", kTypeFloat, kMaxBit16),
                        VariantConstraint("S4", kTypeFloat, kMaxBit32),
                        VariantConstraint("D4", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H5", kTypeFloat, kMaxBit16),
                        VariantConstraint("S5", kTypeFloat, kMaxBit32),
                        VariantConstraint("D5", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H6", kTypeFloat, kMaxBit16),
                        VariantConstraint("S6", kTypeFloat, kMaxBit32),
                        VariantConstraint("D6", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H7", kTypeFloat, kMaxBit16),
                        VariantConstraint("S7", kTypeFloat, kMaxBit32),
                        VariantConstraint("D7", kTypeFloat, kMaxBit64)}),
};

// TODO(pag): Probably totally broken.
static const std::vector<RegisterConstraint> kReturnRegConstraints = {
    RegisterConstraint({VariantConstraint("W0", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X0", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W1", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X1", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W2", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X2", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W3", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X3", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W4", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X4", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W5", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X5", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W6", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X6", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("W7", kTypeIntegral, kMaxBit32),
                        VariantConstraint("X7", kTypeIntegral, kMaxBit64)}),

    RegisterConstraint({VariantConstraint("H0", kTypeFloat, kMaxBit16),
                        VariantConstraint("S0", kTypeFloat, kMaxBit32),
                        VariantConstraint("D0", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H1", kTypeFloat, kMaxBit16),
                        VariantConstraint("S1", kTypeFloat, kMaxBit32),
                        VariantConstraint("D1", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H2", kTypeFloat, kMaxBit16),
                        VariantConstraint("S2", kTypeFloat, kMaxBit32),
                        VariantConstraint("D2", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H3", kTypeFloat, kMaxBit16),
                        VariantConstraint("S3", kTypeFloat, kMaxBit32),
                        VariantConstraint("D3", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H4", kTypeFloat, kMaxBit16),
                        VariantConstraint("S4", kTypeFloat, kMaxBit32),
                        VariantConstraint("D4", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H5", kTypeFloat, kMaxBit16),
                        VariantConstraint("S5", kTypeFloat, kMaxBit32),
                        VariantConstraint("D5", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H6", kTypeFloat, kMaxBit16),
                        VariantConstraint("S6", kTypeFloat, kMaxBit32),
                        VariantConstraint("D6", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("H7", kTypeFloat, kMaxBit16),
                        VariantConstraint("S7", kTypeFloat, kMaxBit32),
                        VariantConstraint("D7", kTypeFloat, kMaxBit64)}),
};

// Used to split things like `i64`s into multiple `i32`s.
static llvm::Type *IntegerTypeSplitter(llvm::Type *type) {
  auto int_ty = llvm::dyn_cast<llvm::IntegerType>(type);
  if (!int_ty) {
    return nullptr;
  }

  auto width = int_ty->getPrimitiveSizeInBits();
  if (width <= 64) {
    return nullptr;
  }

  auto num_elements = (width + 63) / 64;
  auto i64_ty = llvm::Type::getInt64Ty(type->getContext());
  return llvm::ArrayType::get(i64_ty, num_elements);
}

}  // namespace

// This is the only calling convention for 64-bit ARMv8 code.
class AArch64_C : public CallingConvention {
 public:
  explicit AArch64_C(const remill::Arch *arch);
  virtual ~AArch64_C(void) = default;

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
CallingConvention::CreateAArch64_C(const remill::Arch *arch) {
  return std::unique_ptr<CallingConvention>(new AArch64_C(arch));
}

AArch64_C::AArch64_C(const remill::Arch *arch)
    : CallingConvention(llvm::CallingConv::C, arch),
      parameter_register_constraints(kParamRegConstraints),
      return_register_constraints(kReturnRegConstraints) {}

// Allocates the elements of the function signature of func to memory or
// registers. This includes parameters/arguments, return values, and the return
// stack pointer.
llvm::Error AArch64_C::AllocateSignature(FunctionDecl &fdecl,
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

  fdecl.return_address.reg = arch->RegisterByName("X30");
  fdecl.return_address.type = fdecl.return_address.reg->type;

  return llvm::Error::success();
}

llvm::Error
AArch64_C::BindReturnValues(llvm::Function &function, bool &injected_sret,
                            std::vector<anvill::ValueDecl> &ret_values) {

  llvm::Type *ret_type = function.getReturnType();
  injected_sret = false;

  // If there is an sret parameter then it is a special case.
  if (function.hasStructRetAttr()) {
    ret_values.emplace_back();
    auto &value_declaration = ret_values.back();

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
    value_declaration.reg = arch->RegisterByName("X8");
    return llvm::Error::success();
  }

  switch (ret_type->getTypeID()) {
    case llvm::Type::VoidTyID: return llvm::Error::success();

    case llvm::Type::IntegerTyID: {
      const auto *int_ty = llvm::dyn_cast<llvm::IntegerType>(ret_type);
      const auto int32_ty = llvm::Type::getInt32Ty(int_ty->getContext());
      const auto bit_width = int_ty->getBitWidth();
      if (bit_width <= 32) {
        ret_values.emplace_back();
        auto &value_declaration = ret_values.back();
        value_declaration.reg = arch->RegisterByName("X0");
        value_declaration.type = ret_type;
        return llvm::Error::success();

      } else if (bit_width <= 64) {
        ret_values.emplace_back();
        auto &value_declaration = ret_values.back();
        value_declaration.reg = arch->RegisterByName("X0");
        value_declaration.type = ret_type;
        return llvm::Error::success();

      // Split the integer across `X7:X0`. Experimentally, the largest
      // returnable integer is 512 bits in size, any larger and RVO is used.
      } else if (bit_width <= 512) {
        const char *ret_names[] = {"X0", "X1", "X2", "X3",
                                   "X4", "X5", "X6", "X7"};
        for (auto i = 0u; i < 8 && (64 * i) < bit_width; ++i) {
          ret_values.emplace_back();
          auto &value_declaration = ret_values.back();
          value_declaration.reg = arch->RegisterByName(ret_names[i]);
          value_declaration.type = int32_ty;
        }
        return llvm::Error::success();

      // The integer is too big to be split across registers, fall back to
      // return-value optimization.
      } else {
        ret_values.emplace_back();
        auto &value_declaration = ret_values.back();
        value_declaration.type =
            llvm::PointerType::get(value_declaration.type, 0);
        value_declaration.reg = arch->RegisterByName("X8");
        return llvm::Error::success();
      }
    }

    // Pointers always fit into `X0`.
    case llvm::Type::PointerTyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("X0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::HalfTyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("H0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::FloatTyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("S0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::DoubleTyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("D0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::FP128TyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("Q0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    // Try to split the composite type over registers, and fall back on RVO
    // if it's not possible.
    case llvm::Type::VectorTyID:
    case llvm::Type::ArrayTyID:
    case llvm::Type::StructTyID: {
      auto comp_ptr = llvm::dyn_cast<llvm::CompositeType>(ret_type);
      AllocationState alloc_ret(return_register_constraints, arch, this);
      alloc_ret.config.type_splitter = IntegerTypeSplitter;
      auto mapping = alloc_ret.TryRegisterAllocate(*comp_ptr);

      // There is a valid split over registers, so add the mapping
      if (mapping) {
        return alloc_ret.CoalescePacking(mapping.getValue(), ret_values);

      // Composite type splitting; Unlike with x86, LLVM doesn't naturally
      // perform RVO on large structures returned by value from bitcode.
      } else {
        break;
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
AArch64_C::BindParameters(llvm::Function &function, bool injected_sret,
                          std::vector<ParameterDecl> &parameter_declarations) {
  CHECK(!injected_sret)
      << "Injected struct returns are not supported on SPARC targets";

  const auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // Used to keep track of which registers have been allocated
  AllocationState alloc_param(parameter_register_constraints, arch, this);
  alloc_param.config.type_splitter = IntegerTypeSplitter;

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
        parameter_declarations.emplace_back();
        auto &declaration = parameter_declarations.back();
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
      parameter_declarations.emplace_back();
      auto &declaration = parameter_declarations.back();
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
