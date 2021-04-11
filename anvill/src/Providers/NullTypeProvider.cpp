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

#include "NullTypeProvider.h"

namespace anvill {

NullTypeProvider::NullTypeProvider(void) {}

std::optional<FunctionDecl> NullTypeProvider::TryGetFunctionType(uint64_t) {
  return std::nullopt;
}

std::optional<GlobalVarDecl>
NullTypeProvider::TryGetVariableType(uint64_t, const llvm::DataLayout &) {
  return std::nullopt;
}

void NullTypeProvider::QueryRegisterStateAtInstruction(
    uint64_t, uint64_t,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)>) {}

ITypeProvider::Ptr NullTypeProvider::Create(void) {
  return Ptr(new NullTypeProvider());
}

}  // namespace anvill
