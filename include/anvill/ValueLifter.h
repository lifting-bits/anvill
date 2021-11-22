/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
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
  // Returns an `llvm::Constant *` if the pointer is associated with a
  // known or plausible entity, and an `nullptr` otherwise.
  //
  // TODO(pag): Modify to use pointee type.
  llvm::Constant *Lift(uint64_t ea, llvm::PointerType *pointer_type) const;

 private:
  std::shared_ptr<EntityLifterImpl> impl;
};

}  // namespace anvill
