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

#include <anvill/Lifters/ValueLifter.h>

#include <llvm/ADT/APInt.h>
#include <llvm/Support/TypeSize.h>

namespace llvm {
class DataLayout;
}  // namespace llvm
namespace anvill {

class ValueLifterImpl {
 public:
  explicit ValueLifterImpl(llvm::Module &module_);

  // Consume `num_bytes` of bytes from `data`, and update `data` in place.
  llvm::APInt ConsumeValue(std::string_view &data, unsigned num_bytes);

  // Consume `size` bytes of data from `data`, and update `data` in place.
  inline llvm::APInt ConsumeValue(std::string_view &data, llvm::TypeSize size) {
    return ConsumeValue(
        data, static_cast<unsigned>(static_cast<uint64_t>(size)));
  }

  llvm::Constant *Lift(std::string_view data, llvm::Type *type_of_data,
                       const EntityLifter &entity_lifter);

  llvm::Module &module;
  const llvm::DataLayout &dl;
};

}  // namespace anvill
