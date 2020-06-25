/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include <vector>

#include "Arch.h"

#include <remill/BC/Util.h>

#include <llvm/IR/Attributes.h>

namespace remill {

class Arch;

}  // namespace remill
namespace anvill {

class CallingConvention;

struct AllocationConfig {
  bool can_pack_multiple_values_together{false};
  llvm::Type *(*type_splitter)(llvm::Type *) = nullptr;
};

// Captures the state of allocation for registers, including which registers
// are taken and the available space left in each register. The AllocationState
// needs a reference to the working architecture so that it can lookup
// registers.
struct AllocationState {
 public:
  ~AllocationState(void);

  AllocationState(const std::vector<RegisterConstraint> &_constraints,
                  const remill::Arch *_arch, const CallingConvention *_conv);

  SizeAndType AssignSizeAndType(llvm::Type &type);

  llvm::Optional<std::vector<ValueDecl>> TryRegisterAllocate(llvm::Type &type);

  llvm::Optional<std::vector<anvill::ValueDecl>> TryCompositeRegisterAllocate(
      llvm::CompositeType &type);

  llvm::Optional<std::vector<ValueDecl>> TryBasicRegisterAllocate(
      llvm::Type &type, llvm::Optional<SizeAndType> hint);

  llvm::Optional<std::vector<anvill::ValueDecl>> TryVectorRegisterAllocate(
      llvm::VectorType &type);

  bool IsFilled(size_t i);

  uint64_t RemainingSpace(size_t i);

  llvm::Optional<std::vector<anvill::ValueDecl>> ProcessIntVecX86_64SysV(
      llvm::Type *elem_type, unsigned int vec_size, unsigned int bit_width);

  llvm::Error CoalescePacking(
      const std::vector<anvill::ValueDecl> &vector,
      std::vector<anvill::ValueDecl> &packed_values);

  const std::vector<RegisterConstraint> &constraints;
  const remill::Arch *arch;
  std::vector<bool> reserved;
  std::vector<uint64_t> fill;
  const CallingConvention *conv;
  AllocationConfig config;
  const SizeConstraint ptr_size_constraint;
};

}  // namespace anvill
