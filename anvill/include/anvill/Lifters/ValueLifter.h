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
class Type;
class PointerType;
}  // namespace llvm
namespace anvill {

class EntityLifter;
class EntityLifterImpl;

class ValueLifter {
 public:
  ~ValueLifter(void);

  ValueLifter(const EntityLifter &entity_lifter_);

  // Interpret `data` as the backing bytes to initialize an `llvm::Constant`
  // of type `type_of_data`. `loc_ea`, if non-null, is the address at which
  // `data` appears.
  llvm::Constant *Lift(std::string_view data, llvm::Type *type_of_data) const;

  // Interpret `ea` as being a pointer of type `pointer_type`. `loc_ea`,
  // if non-null, is the address at which `ea` appears.
  //
  // Returns an `llvm::GlobalValue *` if the pointer is associated with a
  // known or plausible entity, and an `llvm::Constant *` otherwise.
  llvm::Constant *Lift(uint64_t ea, llvm::PointerType *pointer_type) const;

 private:
  std::shared_ptr<EntityLifterImpl> impl;
};

}  // namespace anvill
