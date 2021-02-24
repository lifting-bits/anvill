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

#include <anvill/Lifters/Options.h>
#include <llvm/ADT/APInt.h>
#include <llvm/Support/TypeSize.h>

namespace llvm {
class Constant;
class DataLayout;
class LLVMContext;
class Type;
}  // namespace llvm
namespace anvill {

class EntityLifterImpl;

// Implementation of the `ValueLifter`.
class ValueLifter {
 public:
  explicit ValueLifter(const LifterOptions &options_);

  // Consume `num_bytes` of bytes from `data`, interpreting them as an integer,
  // and update `data` in place, bumping out the first `num_bytes` of consumed
  // data.
  llvm::APInt ConsumeBytesAsInt(std::string_view &data,
                                unsigned num_bytes) const;

  // Consume `size` bytes of data from `data`, and update `data` in place.
  inline llvm::APInt ConsumeBytesAsInt(std::string_view &data,
                                       llvm::TypeSize size) const {
    return ConsumeBytesAsInt(
        data, static_cast<unsigned>(static_cast<uint64_t>(size)));
  }

  // Interpret `data` as the backing bytes to initialize an `llvm::Constant`
  // of type `type_of_data`. This requires access to `ent_lifter` to be able
  // to lift pointer types that will reference declared data/functions.
  llvm::Constant *Lift(std::string_view data, llvm::Type *type_of_data,
                       EntityLifterImpl &ent_lifter) const;

  const LifterOptions options;
  const llvm::DataLayout &dl;
  llvm::LLVMContext &context;
};

}  // namespace anvill
