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

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>
          typed_reg_cb) final;

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

// Try to get the type of the register named `reg_name` on entry to the
// instruction at `inst_address` inside the function beginning at
// `func_address`.
void ProgramTypeProvider::QueryRegisterStateAtInstruction(
    uint64_t func_address, uint64_t inst_address,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)>
        typed_reg_cb) {

  auto decl = program.FindFunction(func_address);
  if (!decl) {
    return;
  }

  auto types_it = decl->reg_info.find(inst_address);
  if (types_it == decl->reg_info.end()) {
    return;
  }

  for (const auto &decl : types_it->second) {
    typed_reg_cb(decl.reg->name, decl.type, decl.value);
  }
}

}  // namespace

TypeProvider::~TypeProvider(void) {}

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

}  // namespace anvill