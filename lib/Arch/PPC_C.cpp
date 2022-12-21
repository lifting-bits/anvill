/*
 * Copyright (c) 2022-present Trail of Bits, Inc.
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

#include <anvill/Declarations.h>
#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>

#include "AllocationState.h"
#include "Arch.h"

namespace anvill {
namespace {

static const std::vector<RegisterConstraint> kParamRegConstraints = {
    // GPRs
    RegisterConstraint({VariantConstraint("R3", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R4", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R5", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R6", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R7", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R8", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R9", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R10", kTypeIntegral, kMaxBit32)}),
    // FPRs
    RegisterConstraint({VariantConstraint("F1", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F2", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F3", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F4", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F5", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F6", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F7", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F8", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F9", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F10", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F11", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F12", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F13", kTypeFloat, kMaxBit32)}),
};

static const std::vector<RegisterConstraint> kReturnRegConstraints = {
    // GPRs
    RegisterConstraint({VariantConstraint("R3", kTypeIntegral, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("R4", kTypeIntegral, kMaxBit32)}),
    // FPRs
    RegisterConstraint({VariantConstraint("F1", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F2", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F3", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("F4", kTypeFloat, kMaxBit32)}),
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

class PPC_C : public CallingConvention {
 public:
  explicit PPC_C(const remill::Arch *arch);
  virtual ~PPC_C() = default;

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
CallingConvention::CreatePPC_C(const remill::Arch *arch) {
  return std::make_unique<PPC_C>(arch);
}

PPC_C::PPC_C(const remill::Arch *arch)
    : CallingConvention(llvm::CallingConv::C, arch),
      parameter_register_constraints(kParamRegConstraints),
      return_register_constraints(kReturnRegConstraints) {}

llvm::Error PPC_C::AllocateSignature(FunctionDecl &fdecl,
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
  fdecl.return_stack_pointer = arch->RegisterByName("R1");

  fdecl.return_address.reg = arch->RegisterByName("LR");
  fdecl.return_address.type = fdecl.return_address.reg->type;

  return llvm::Error::success();
}

llvm::Error
PPC_C::BindReturnValues(llvm::Function &function, bool &injected_sret,
                        std::vector<anvill::ValueDecl> &ret_values) {

  llvm::Type *ret_type = function.getReturnType();
  LOG(INFO) << "Binding on return " << remill::LLVMThingToString(ret_type);
  injected_sret = false;

  // If there is an sret parameter then it is a special case.
  if (function.hasStructRetAttr()) {
    auto &value_declaration = ret_values.emplace_back();

    value_declaration.type = llvm::PointerType::get(function.getContext(), 0);

    if (!ret_type->isVoidTy()) {
      return llvm::createStringError(
          std::errc::invalid_argument,
          "Function '%s' with sret-attributed parameter has non-void return type '%s'",
          function.getName().str().c_str(),
          remill::LLVMThingToString(ret_type).c_str());
    }

    // NOTE(alex): Not sure about this, check later.
    //
    // Indirect return values are passed by pointer through `R3`.
    value_declaration.reg = arch->RegisterByName("R3");
    return llvm::Error::success();
  }

  switch (ret_type->getTypeID()) {
    case llvm::Type::VoidTyID: return llvm::Error::success();

    case llvm::Type::IntegerTyID: {
      const auto *int_ty = llvm::dyn_cast<llvm::IntegerType>(ret_type);
      const auto int64_ty = llvm::Type::getInt64Ty(int_ty->getContext());
      const auto bit_width = int_ty->getBitWidth();
      if (bit_width <= 64) {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName("R3");
        value_declaration.type = ret_type;
        return llvm::Error::success();

        // Split the integer across `R3` and `R4`.
      } else if (bit_width <= 128) {
        const char *ret_names[] = {"R3", "R4"};
        for (auto i = 0u; i < 2 && (64 * i) < bit_width; ++i) {
          auto &value_declaration = ret_values.emplace_back();
          value_declaration.reg = arch->RegisterByName(ret_names[i]);
          value_declaration.type = int64_ty;
        }
        return llvm::Error::success();

        // The integer is too big to be split across registers, fall back to
        // return-value optimization.
      } else {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.type =
            llvm::PointerType::get(function.getContext(), 0);
        value_declaration.reg = arch->RegisterByName("R3");
        return llvm::Error::success();
      }
    }

    // Pointers always fit into `R3`.
    case llvm::Type::PointerTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("R3");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::HalfTyID:
    case llvm::Type::FloatTyID:
    case llvm::Type::DoubleTyID: {
      auto &value_declaration = ret_values.emplace_back();
      value_declaration.reg = arch->RegisterByName("F1");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::FP128TyID: {

      // double types gets split into two integer registers
      const auto fp128_ty = llvm::Type::getDoubleTy(ret_type->getContext());

      // get the primitive type size to split them to registers
      const auto bit_width = fp128_ty->getScalarSizeInBits();
      const char *reg_names[] = {"F1", "F2"};
      for (auto i = 0u; i < 2 && (64 * i) < bit_width; ++i) {
        auto &value_declaration = ret_values.emplace_back();
        value_declaration.reg = arch->RegisterByName(reg_names[i]);
        value_declaration.type = fp128_ty;
      }
      return llvm::Error::success();
    }

    // Try to split the composite type over registers, and fall back on RVO
    // if it's not possible.
    case llvm::Type::FixedVectorTyID:
    case llvm::Type::ArrayTyID:
    case llvm::Type::StructTyID: {
      AllocationState alloc_ret(return_register_constraints, arch, this);
      alloc_ret.config.type_splitter = IntegerTypeSplitter;
      auto mapping = alloc_ret.TryRegisterAllocate(*ret_type);

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
PPC_C::BindParameters(llvm::Function &function, bool injected_sret,
                      std::vector<ParameterDecl> &parameter_declarations) {

  const auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // Used to keep track of which registers have been allocated
  AllocationState alloc_param(parameter_register_constraints, arch, this);
  alloc_param.config.type_splitter = IntegerTypeSplitter;

  unsigned stack_offset = 0;
  const auto sp_reg = arch->RegisterByName("R1");

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
