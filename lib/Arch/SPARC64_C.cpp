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

#include "Arch.h"

#include <glog/logging.h>

#include <anvill/Decl.h>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>

#include "AllocationState.h"

namespace anvill {
namespace {

static const std::vector<RegisterConstraint> kParamRegConstraints = {
    RegisterConstraint({VariantConstraint("o0", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o1", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o2", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o3", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o4", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o5", kTypeIntegral, kMaxBit64)}),

    RegisterConstraint({VariantConstraint("f1", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f3", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f5", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f7", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f9", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f11", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f13", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f15", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f17", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f19", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f21", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f23", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f25", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f27", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f29", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f31", kTypeFloat, kMaxBit32)}),

    RegisterConstraint({VariantConstraint("d0", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d2", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d4", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d6", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d8", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d10", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d12", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d14", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d16", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d18", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d20", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d22", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d24", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d26", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d28", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d30", kTypeFloat, kMaxBit64)}),

    RegisterConstraint({VariantConstraint("q0", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q4", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q8", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q12", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q16", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q20", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q24", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q28", kTypeFloat, kMaxBit128)}),
};

static const std::vector<RegisterConstraint> kReturnRegConstraints = {
    RegisterConstraint({VariantConstraint("o0", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o1", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o2", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o3", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o4", kTypeIntegral, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("o5", kTypeIntegral, kMaxBit64)}),

    RegisterConstraint({VariantConstraint("f0", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f1", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f2", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f3", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f4", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f5", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f6", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f7", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f8", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f9", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f10", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f11", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f12", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f13", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f14", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f15", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f16", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f17", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f18", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f19", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f20", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f21", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f22", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f23", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f24", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f25", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f26", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f27", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f28", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f29", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f30", kTypeFloat, kMaxBit32)}),
    RegisterConstraint({VariantConstraint("f31", kTypeFloat, kMaxBit32)}),

    RegisterConstraint({VariantConstraint("d0", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d2", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d4", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d6", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d8", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d10", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d12", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d14", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d16", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d18", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d20", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d22", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d24", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d26", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d28", kTypeFloat, kMaxBit64)}),
    RegisterConstraint({VariantConstraint("d30", kTypeFloat, kMaxBit64)}),

    RegisterConstraint({VariantConstraint("q0", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q4", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q8", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q12", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q16", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q20", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q24", kTypeFloat, kMaxBit128)}),
    RegisterConstraint({VariantConstraint("q28", kTypeFloat, kMaxBit128)}),
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

// This is the only calling convention for 32-bit SPARC code.
class SPARC64_C : public CallingConvention {
 public:
   explicit SPARC64_C(const remill::Arch *arch);
   virtual ~SPARC64_C(void) = default;

   llvm::Error AllocateSignature(FunctionDecl &fdecl,
                                 llvm::Function &func) override;

  private:
   llvm::Error BindParameters(llvm::Function &function, bool injected_sret,
                              std::vector<ParameterDecl> &param_decls);

   llvm::Error BindReturnValues(llvm::Function &function,
                                bool &injected_sret,
                                std::vector<ValueDecl> &ret_decls);

   const std::vector<RegisterConstraint> &parameter_register_constraints;
   const std::vector<RegisterConstraint> &return_register_constraints;
};

std::unique_ptr<CallingConvention> CallingConvention::CreateSPARC64_C(
      const remill::Arch *arch) {
  return std::unique_ptr<CallingConvention>(new SPARC64_C(arch));
}

SPARC64_C::SPARC64_C(const remill::Arch *arch)
    : CallingConvention(llvm::CallingConv::C, arch),
      parameter_register_constraints(kParamRegConstraints),
      return_register_constraints(kReturnRegConstraints) {}

// Allocates the elements of the function signature of func to memory or
// registers. This includes parameters/arguments, return values, and the return
// stack pointer.
llvm::Error SPARC64_C::AllocateSignature(FunctionDecl &fdecl,
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
  fdecl.return_stack_pointer = arch->RegisterByName("o6");

  fdecl.return_address.reg = arch->RegisterByName("o7");
  fdecl.return_address.type = fdecl.return_address.reg->type;

  return llvm::Error::success();
}

llvm::Error SPARC64_C::BindReturnValues(
    llvm::Function &function, bool &injected_sret,
    std::vector<anvill::ValueDecl> &ret_values) {

  llvm::Type *ret_type = function.getReturnType();
  injected_sret = false;

  // If there is an sret parameter then it is a special case. For the X86_C ABI,
  // the sret parameters are guarenteed the be in %eax. In this case, we can
  // assume the actual return value of the function will be the sret struct
  // pointer.
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

    value_declaration.type = llvm::PointerType::get(
        value_declaration.type, 0);

    if (!ret_type->isVoidTy()) {
      return llvm::createStringError(
          std::errc::invalid_argument,
          "Function '%s' with sret-attributed parameter has non-void return type '%s'",
          function.getName().str().c_str(),
          remill::LLVMThingToString(ret_type).c_str());
    }

    value_declaration.reg = arch->RegisterByName("o0");
    return llvm::Error::success();
  }

  switch (ret_type->getTypeID()) {
    case llvm::Type::VoidTyID:
      return llvm::Error::success();

    case llvm::Type::IntegerTyID: {
      const auto *int_ty = llvm::dyn_cast<llvm::IntegerType>(ret_type);
      const auto int32_ty = llvm::Type::getInt32Ty(int_ty->getContext());
      const auto bit_width = int_ty->getBitWidth();

      if (bit_width <= 64) {
        ret_values.emplace_back();
        auto &value_declaration = ret_values.back();
        value_declaration.reg = arch->RegisterByName("o0");
        value_declaration.type = ret_type;
        return llvm::Error::success();

      // Split the integer across `o5:o0`. Experimentally, the largest
      // returnable integer is 384 bits in size, any larger and LLVM crashes.
      } else if (bit_width <= 384) {
        const char *ret_names[] = {"o0", "o1", "o2", "o3", "o4", "o5"};
        for (auto i = 0u; i < 6 && (64 * i) < bit_width; ++i) {
          ret_values.emplace_back();
          auto &value_declaration = ret_values.back();
          value_declaration.reg = arch->RegisterByName(ret_names[i]);
          value_declaration.type = int32_ty;
        }
        return llvm::Error::success();
      } else {
        return llvm::createStringError(
            std::errc::invalid_argument,
            "Could not allocate integral type '%s' to return register(s) in function '%s'",
            remill::LLVMThingToString(ret_type).c_str(),
            function.getName().str().c_str());
      }
    }

    // Pointers always fit into `EAX`.
    case llvm::Type::PointerTyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("o0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::HalfTyID:
    case llvm::Type::FloatTyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("f0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::DoubleTyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("d0");
      value_declaration.type = ret_type;
      return llvm::Error::success();
    }

    case llvm::Type::FP128TyID: {
      ret_values.emplace_back();
      auto &value_declaration = ret_values.back();
      value_declaration.reg = arch->RegisterByName("q0");
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

    default:
      break;
  }

  return llvm::createStringError(
      std::errc::invalid_argument,
      "Could not allocate unsupported type '%s' to return register in function '%s'",
      remill::LLVMThingToString(ret_type).c_str(),
      function.getName().str().c_str());
}

// For X86_64_SysV, the general argument passing behavior is, try to pass the
// arguments in registers RDI, RSI, RDX, RCX, R8, R9 from integral types and
// XMM0 - XMM7 for float types. If the argument is a struct but can be
// completely split over the above registers, then greedily split it over the
// registers. Otherwise, the struct is passed entirely on the stack. If we run
// our of registers then pass the rest of the arguments on the stack.
llvm::Error SPARC64_C::BindParameters(
    llvm::Function &function, bool injected_sret,
    std::vector<ParameterDecl> &parameter_declarations) {
  CHECK(!injected_sret)
      << "Injected struct returns are not supported on SPARC targets";

  const auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // Used to keep track of which registers have been allocated
  AllocationState alloc_param(parameter_register_constraints, arch, this);
  alloc_param.config.type_splitter = IntegerTypeSplitter;

  // The stack bias for SPARC V9 ABI on solaris is 2047
  // https://docs.oracle.com/cd/E18752_01/html/816-5138/advanced-2.html#advanced-5
  uint64_t stack_offset = 2047;
  //uint64_t stack_offset = 2227;

  const auto sp_reg = arch->RegisterByName("o6");

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
        for (auto i = 0u; i < (parameter_declarations.size() - prev_size); ++i) {
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
