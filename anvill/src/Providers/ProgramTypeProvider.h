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
#include <anvill/Providers/ITypeProvider.h>
#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <remill/BC/Util.h>

namespace anvill {

// Provider of memory wrapping around an `anvill::Program`.
class ProgramTypeProvider final : public ITypeProvider {
 public:
  static Ptr Create(const IProgram &program, llvm::LLVMContext &context);
  virtual ~ProgramTypeProvider(void) override;

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  virtual std::optional<FunctionDecl>
  TryGetFunctionType(uint64_t address) override;

  virtual std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t address, const llvm::DataLayout &layout) override;

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  virtual void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>
          typed_reg_cb) override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ProgramTypeProvider(llvm::LLVMContext &context, const Program &program);
};

}  // namespace anvill
