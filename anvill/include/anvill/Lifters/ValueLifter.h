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

class ValueLifterImpl;

class EntityLifter;

// The value lifter is responsible for lifting raw data, as taken from
// memory, and producing `llvm::Constant` values that can be used to initialize
// global variables.
class ValueLifter {
 public:
  ~ValueLifter(void);

  explicit ValueLifter(llvm::Module &module_);

  llvm::Constant *Lift(std::string_view data, llvm::Type *type_of_data,
                       const EntityLifter &entity_lifter) const;

 private:
  friend class DataLifter;
  friend class FunctionLifter;

  ValueLifter(void) = delete;
  std::shared_ptr<ValueLifterImpl> impl;
};

}  // namespace anvill
