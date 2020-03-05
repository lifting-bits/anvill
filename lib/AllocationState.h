#pragma once

#include <vector>

#include "Arch/Arch.h"
#include "anvill/Decl.h"

#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <llvm/IR/Attributes.h>

namespace anvill {

// Captures the state of allocation for registers, including which registers
// are taken and the available space left in each register. The AllocationState
// needs a reference to the working architecture so that it can lookup
// registers.
struct AllocationState {
  AllocationState(const std::vector<RegisterConstraint> &_constraints,
                  const remill::Arch *_arch, const CallingConvention *_conv)
      : constraints(_constraints),
        arch(_arch),
        reserved(_constraints.size(), false),
        fill(constraints.size(), 0),
        conv(_conv) {}

  const std::vector<RegisterConstraint> &constraints;
  const remill::Arch *arch;
  std::vector<bool> reserved;
  std::vector<uint64_t> fill;
  const CallingConvention *conv;

  static SizeAndType AssignSizeAndType(llvm::Type &type);
  llvm::Optional<std::vector<ValueDecl>> TryRegisterAllocate(llvm::Type &type,
                                                             bool pack);
  llvm::Optional<std::vector<anvill::ValueDecl>> TryCompositeRegisterAllocate(
      llvm::CompositeType &type);
  llvm::Optional<std::vector<ValueDecl>> TryBasicRegisterAllocate(
      llvm::Type &type, llvm::Optional<SizeAndType> hint, bool pack);
  llvm::Optional<std::vector<anvill::ValueDecl>> TryVectorRegisterAllocate(
      llvm::VectorType &type);
  bool isFilled(size_t i);
  uint64_t getRemainingSpace(size_t i);
  llvm::Optional<std::vector<anvill::ValueDecl>> ProcessIntVecX86_64SysV(
      llvm::Type *elem_type, unsigned int vec_size, unsigned int bit_width);
  std::vector<anvill::ValueDecl> CoalescePacking(
      const std::vector<anvill::ValueDecl> &vector);
};

}  // namespace anvill