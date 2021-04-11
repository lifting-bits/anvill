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
#include <anvill/Providers/ITypeProvider.h>
#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <remill/BC/Util.h>

namespace anvill {

class NullTypeProvider final : public ITypeProvider {
 public:
  static Ptr Create(void);
  virtual ~NullTypeProvider(void) override;

  std::optional<FunctionDecl> TryGetFunctionType(uint64_t) override;

  std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t, const llvm::DataLayout &) override;

  virtual void QueryRegisterStateAtInstruction(
      uint64_t, uint64_t,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>) override;

 private:
  NullTypeProvider(void);
};

}  // namespace anvill
