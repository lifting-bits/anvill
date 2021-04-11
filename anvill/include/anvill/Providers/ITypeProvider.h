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

#pragma once

#include <anvill/Decl.h>
#include <anvill/IProgram.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace anvill {

// Provides bytes of memory from some source.
class ITypeProvider {
 public:
  using Ptr = std::unique_ptr<ITypeProvider>;

  static Ptr CreateFromProgram(llvm::LLVMContext &context,
                               const IProgram &program);
  static Ptr CreateNull();

  virtual ~ITypeProvider(void) = default;
  ITypeProvider() = default;

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  virtual std::optional<FunctionDecl> TryGetFunctionType(uint64_t address) = 0;

  // Try to return the variable at given address or containing the address
  virtual std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t address, const llvm::DataLayout &layout) = 0;

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  virtual void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>
          typed_reg_cb) = 0;

  ITypeProvider(const ITypeProvider &) = delete;
  ITypeProvider(ITypeProvider &&) noexcept = delete;

  ITypeProvider &operator=(const ITypeProvider &) = delete;
  ITypeProvider &operator=(ITypeProvider &&) noexcept = delete;
};

}  // namespace anvill
