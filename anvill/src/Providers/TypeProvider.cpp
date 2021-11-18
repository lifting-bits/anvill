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

#include <anvill/Decl.h>
#include <anvill/Program.h>
#include <anvill/Providers/TypeProvider.h>
#include <glog/logging.h>
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
  explicit ProgramTypeProvider(llvm::LLVMContext &context_,
                               const Program &program_)
      : TypeProvider(context_),
        program(program_) {}

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  std::optional<FunctionDecl> TryGetFunctionType(uint64_t address) final;

  std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t address, const llvm::DataLayout &layout) final;

 private:
  ProgramTypeProvider(void) = delete;

  const Program &program;
};

// Try to return the type of a function starting at address `address`. This
// type is the prototype of the function.
std::optional<FunctionDecl>
ProgramTypeProvider::TryGetFunctionType(uint64_t address) {
  const auto decl = program.FindFunction(address);
  if (!decl) {
    return std::nullopt;
  }

  CHECK_NOTNULL(decl->type);
  CHECK_EQ(decl->address, address);

  return *decl;
}

std::optional<GlobalVarDecl>
ProgramTypeProvider::TryGetVariableType(uint64_t address,
                                        const llvm::DataLayout &layout) {
  if (auto var_decl = program.FindVariable(address); var_decl) {

    // Check integrity of the var_decl
    CHECK_NOTNULL(var_decl->type);
    CHECK_EQ(var_decl->address, address);
    return *var_decl;

  // if FindVariable fails to get the variable at address; get the variable
  // containing the address
  } else if (auto var_decl = program.FindInVariable(address, layout);
             var_decl) {
    CHECK_NOTNULL(var_decl->type);
    CHECK_LE(var_decl->address, address);
    return *var_decl;
  }

  return std::nullopt;
}

class NullTypeProvider final : public TypeProvider {
 public:
  NullTypeProvider(llvm::LLVMContext &context_) : TypeProvider(context_) {}

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  std::optional<FunctionDecl> TryGetFunctionType(uint64_t) final {
    return std::nullopt;
  }

  std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t, const llvm::DataLayout &) final {
    return std::nullopt;
  }

 private:
  NullTypeProvider(void) = delete;
};


}  // namespace

TypeProvider::~TypeProvider(void) {}

// Try to return the type of a function starting at address `to_address`. This
// type is the prototype of the function. The type can be call site specific,
// where the call site is `from_inst`.
std::optional<FunctionDecl> TypeProvider::TryGetCalledFunctionType(
    const remill::Instruction &from_inst, uint64_t to_address) {
  auto decl = TryGetCalledFunctionType(from_inst);
  if (!decl) {
    return TryGetFunctionType(to_address);
  } else {
    return decl;
  }
}

// Try to return the type of a function that has been called from `from_isnt`.
std::optional<FunctionDecl> TypeProvider::TryGetCalledFunctionType(
    const remill::Instruction &) {
  return std::nullopt;
}

TypeProvider::TypeProvider(llvm::LLVMContext &context_) : context(context_) {}

// Try to get the type of the register named `reg_name` on entry to the
// instruction at `inst_address` inside the function beginning at
// `func_address`.
void TypeProvider::QueryRegisterStateAtInstruction(
    uint64_t, uint64_t,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)>) {}

// Sources bytes from an `anvill::Program`.
std::shared_ptr<TypeProvider>
TypeProvider::CreateProgramTypeProvider(llvm::LLVMContext &context_,
                                        const Program &program) {
  return std::make_shared<ProgramTypeProvider>(context_, program);
}

// Creates a type provider that always fails to provide type information.
std::shared_ptr<TypeProvider>
TypeProvider::CreateNullTypeProvider(llvm::LLVMContext &context_) {
  return std::make_shared<NullTypeProvider>(context_);
}

}  // namespace anvill
