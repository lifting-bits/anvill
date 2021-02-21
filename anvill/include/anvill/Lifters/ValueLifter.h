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

#include <memory>
#include <string_view>

namespace llvm {
class Constant;
class Module;
class Type;
}  // namespace llvm
namespace anvill {

class EntityLifterImpl;

class EntityLifter;
class LifterOptions;

// The value lifter is responsible for lifting raw data, as taken from
// memory, and producing `llvm::Constant` values that can be used to initialize
// global variables.
class ValueLifter {
 public:
  ~ValueLifter(void);

  explicit ValueLifter(const EntityLifter &entity_lifter_);

  // Lift the bytes in `data` as an `llvm::Constant` into the module associated
  // with `entity_lifter_`s options. This may produce an `llvm::Constant`
  // that requires relocations, i.e. that depends on aliases or functions in
  // `options_.module`, i.e. if we're lifting some data where the types contain
  // pointer types, and thus we need to interpret bytes from `data` as being
  // addresses and then lift them to pointers.
  llvm::Constant *Lift(std::string_view data, llvm::Type *type_of_data) const;

  ValueLifter(const ValueLifter &) = default;
  ValueLifter(ValueLifter &&) noexcept = default;
  ValueLifter &operator=(const ValueLifter &) = default;
  ValueLifter &operator=(ValueLifter &&) noexcept = default;

 private:
  friend class DataLifter;
  friend class EntityLifter;
  friend class FunctionLifterImpl;

  inline ValueLifter(const std::shared_ptr<EntityLifterImpl> &impl_)
      : impl(impl_) {}

  ValueLifter(void) = delete;
  std::shared_ptr<EntityLifterImpl> impl;
};

}  // namespace anvill
