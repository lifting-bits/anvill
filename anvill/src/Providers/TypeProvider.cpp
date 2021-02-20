/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <anvill/Providers/TypeProvider.h>

#include <anvill/Program.h>
#include <anvill/Decl.h>

#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>

#include <remill/BC/Util.h>

namespace anvill {
namespace {

// Provider of memory wrapping around an `anvill::Program`.
class ProgramTypeProvider final : public TypeProvider {
 public:

  virtual ~ProgramTypeProvider(void) = default;

  explicit ProgramTypeProvider(llvm::LLVMContext &context_,
                               const Program &program_)
      : context(context_),
        program(program_) {}

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  std::pair<llvm::FunctionType *, llvm::CallingConv::ID>
  TryGetFunctionType(uint64_t address) final;

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)> typed_reg_cb) final;

 private:
  ProgramTypeProvider(void) = delete;

  llvm::LLVMContext &context;
  const Program &program;
};

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::pair<llvm::FunctionType *, llvm::CallingConv::ID>
ProgramTypeProvider::TryGetFunctionType(uint64_t address) {
  const auto decl = program.FindFunction(address);
  if (!decl) {
    return {nullptr, llvm::CallingConv::C};
  }

  llvm::FunctionType *func_type = nullptr;

  if (!decl->type) {
    // Figure out the return type of this function based off the return
    // values.
    llvm::Type *ret_type = nullptr;
    if (decl->returns.empty()) {
      ret_type = llvm::Type::getVoidTy(context);

    } else if (decl->returns.size() == 1) {
      ret_type = decl->returns[0].type;

    // The multiple return value case is most interesting, and somewhere
    // where we see some divergence between C and what we will decompile.
    // For example, on 32-bit x86, a 64-bit return value might be spread
    // across EAX:EDX. Instead of representing this by a single value, we
    // represent it as a structure if two 32-bit ints, and make sure to say
    // that one part is in EAX, and the other is in EDX.
    } else {
      llvm::SmallVector<llvm::Type *, 8> ret_types;
      for (auto &ret_val : decl->returns) {
        ret_types.push_back(ret_val.type);
      }
      ret_type = llvm::StructType::get(context, ret_types, true);
    }

    llvm::SmallVector<llvm::Type *, 8> param_types;
    for (auto &param_val : decl->params) {
      param_types.push_back(param_val.type);
    }

    func_type = llvm::FunctionType::get(ret_type, param_types, decl->is_variadic);

  } else {
    func_type = llvm::dyn_cast<llvm::FunctionType>(
        remill::RecontextualizeType(decl->type, context));
  }

  return {func_type, decl->calling_convention};
}

// Try to get the type of the register named `reg_name` on entry to the
// instruction at `inst_address` inside the function beginning at
// `func_address`.
void ProgramTypeProvider::QueryRegisterStateAtInstruction(
    uint64_t func_address, uint64_t inst_address,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)> typed_reg_cb) {

  auto decl = program.FindFunction(func_address);
  if (!decl) {
    return;
  }

  auto types_it = decl->reg_info.find(inst_address);
  if (types_it == decl->reg_info.end()) {
    return;
  }

  for (const auto &decl : types_it->second) {
    typed_reg_cb(decl.reg, decl.type, decl.value);
  }
}

}  // namespace

TypeProvider::~TypeProvider(void) {}

// Try to get the type of the register named `reg_name` on entry to the
// instruction at `inst_address` inside the function beginning at
// `func_address`.
void TypeProvider::QueryRegisterStateAtInstruction(
    uint64_t, uint64_t,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)>) {}

// Sources bytes from an `anvill::Program`.
std::shared_ptr<TypeProvider> TypeProvider::CreateProgramTypeProvider(
    llvm::LLVMContext &context_, const Program &program) {
  return std::make_shared<ProgramTypeProvider>(context_, program);
}

}  // namespace anvill
