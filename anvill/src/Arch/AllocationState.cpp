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

#include "AllocationState.h"

#include <glog/logging.h>
#include <llvm/IR/Attributes.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Compat/VectorType.h>

#include <algorithm>

namespace anvill {
namespace {

// Converts size constraints to reasonable sizes.
static uint64_t SizeConstraintToSize(const SizeConstraint &sc) {
  switch (sc) {
    case kMaxBit512:
    case kMinBit512: return 512;
    case kMaxBit256:
    case kMinBit256: return 256;
    case kMaxBit128:
    case kMinBit128: return 128;
    case kMaxBit80:
    case kMinBit80: return 80;
    case kMaxBit64:
    case kMinBit64: return 64;
    case kMaxBit32:
    case kMinBit32: return 32;
    case kMaxBit16:
    case kMinBit16: return 16;
    case kMaxBit8:
      return 8;

      // kMinBit8 is a duplicate so it is not included here.
    default: {
      LOG(FATAL) << "Could not handle size constraint";
      return 0;
    }
  }
}

static const std::string kEmptyRegName;

// Get the name of the smallest possible variant that still fits size.
static const std::string &
GetSmallestVariantName(const std::vector<VariantConstraint> &variants,
                       uint64_t size) {
  for (const auto &vc : variants) {
    if (SizeConstraintToSize(vc.size_constraint) >= size) {
      return vc.register_name;
    }
  }
  return kEmptyRegName;
}

}  // namespace

AllocationState::~AllocationState(void) {}

AllocationState::AllocationState(
    const std::vector<RegisterConstraint> &_constraints,
    const remill::Arch *_arch, const CallingConvention *_conv)
    : constraints(_constraints),
      arch(_arch),
      reserved(_constraints.size(), false),
      fill(constraints.size(), 0),
      conv(_conv),
      ptr_size_constraint(arch->address_size == 32 ? kMinBit32 : kMinBit64) {}

// Returns whether or not the register at index i is completely filled
bool AllocationState::IsFilled(size_t i) {
  return RemainingSpace(i) == 0;
}

// Gets the remaining space left in register at index i. Assume that the
// largest register variant is at the back of the variants vector.
uint64_t AllocationState::RemainingSpace(size_t i) {
  return SizeConstraintToSize(constraints[i].variants.back().size_constraint) -
         fill[i];
}

// Assigns a SizeConstraint and TypeConstraint to the given type. This logic is
// separated from the register allocation because in certain edge cases, we
// might need to alter the types and or size that this function returns before
// passing that information to TryRegisterAllocate.
SizeAndType AllocationState::AssignSizeAndType(llvm::Type &type) {
  SizeConstraint size_constraint;
  TypeConstraint type_constraint;

  switch (type.getTypeID()) {
    case llvm::Type::IntegerTyID: {
      type_constraint = kTypeInt;
      auto derived = llvm::cast<llvm::IntegerType>(&type);
      unsigned int width = derived->getBitWidth();
      if (width <= 8) {
        size_constraint = kMinBit8;
      } else if (width <= 16) {
        size_constraint = kMinBit16;
      } else if (width <= 32) {
        size_constraint = kMinBit32;
      } else if (width <= 64) {
        size_constraint = kMinBit64;
      } else if (width <= 80) {
        size_constraint = kMinBit80;
      } else if (width <= 128) {
        size_constraint = kMinBit128;
      } else if (width <= 256) {
        size_constraint = kMinBit256;
      } else if (width <= 512) {
        size_constraint = kMinBit512;
      } else {
        LOG(FATAL) << "Integer too big: " << remill::LLVMThingToString(derived);
      }
      break;
    }
    case llvm::Type::HalfTyID:
      type_constraint = kTypeFloat;
      size_constraint = kMinBit16;
      break;

    case llvm::Type::FloatTyID:
      type_constraint = kTypeFloat;
      size_constraint = kMinBit32;
      break;

    case llvm::Type::DoubleTyID:
      type_constraint = kTypeFloat;
      size_constraint = kMinBit64;
      break;

    case llvm::Type::FP128TyID:
      type_constraint = kTypeFloat;
      size_constraint = kMinBit128;
      break;

    case llvm::Type::PointerTyID:
      type_constraint = kTypeIntegral;
      size_constraint = ptr_size_constraint;
      break;

    case llvm::Type::X86_FP80TyID:
      type_constraint = kTypeIntegral;
      size_constraint = kMinBit80;
      break;

    case llvm::GetFixedVectorTypeId():
      type_constraint = kTypeFloatOrVec;
      size_constraint = kMinBit80;
      break;

    default:
      LOG(FATAL) << "Could not assign type and size constraints for type"
                 << remill::LLVMThingToString(&type);

      // TODO(aty): Handle other types like X86_MMXTyID, etc.
      break;
  }

  return {size_constraint, type_constraint};
}

llvm::Optional<std::vector<ValueDecl>>
AllocationState::TryRegisterAllocate(llvm::Type &type) {
  if (type.isStructTy() || type.isArrayTy() || type.isVectorTy()) {
    return TryCompositeRegisterAllocate(type);
  } else {
    return TryBasicRegisterAllocate(type, llvm::None);
  }
}

llvm::Optional<std::vector<ValueDecl>>
AllocationState::TryCompositeRegisterAllocate(llvm::Type &type) {
  DCHECK(type.isStructTy() || type.isArrayTy() || type.isVectorTy());
  std::vector<ValueDecl> ret;
  if (auto st = llvm::dyn_cast<llvm::StructType>(&type)) {
    for (unsigned i = 0; i < st->getNumElements(); i++) {
      llvm::Type *elem_type = st->getElementType(i);
      const auto prev_pack = config.can_pack_multiple_values_together;
      config.can_pack_multiple_values_together = true;
      if (auto inner = TryRegisterAllocate(*elem_type); inner) {
        config.can_pack_multiple_values_together = prev_pack;
        ret.insert(ret.end(), inner->begin(), inner->end());
      } else {
        config.can_pack_multiple_values_together = prev_pack;
        return llvm::None;
      }
    }

  // Arrays must be of a uniform type
  } else if (auto arr = llvm::dyn_cast<llvm::ArrayType>(&type)) {
    llvm::Type *elem_type = arr->getArrayElementType();
    for (unsigned i = 0; i < arr->getNumElements(); i++) {
      const auto prev_pack = config.can_pack_multiple_values_together;
      config.can_pack_multiple_values_together = true;
      if (auto inner = TryRegisterAllocate(*elem_type); inner) {
        config.can_pack_multiple_values_together = prev_pack;
        ret.insert(ret.end(), inner->begin(), inner->end());
      } else {
        config.can_pack_multiple_values_together = prev_pack;
        return llvm::None;
      }
    }
  } else if (auto vec = llvm::dyn_cast<llvm::FixedVectorType>(&type)) {
    if (auto inner = TryVectorRegisterAllocate(*vec); inner) {
      ret.insert(ret.end(), inner->begin(), inner->end());
    }
  } else {
    LOG(FATAL) << "Trying to allocate for an unknown composite type: "
               << remill::LLVMThingToString(&type);
  }
  return ret;
}

llvm::Optional<std::vector<ValueDecl>>
AllocationState::TryBasicRegisterAllocate(llvm::Type &type,
                                          llvm::Optional<SizeAndType> hint) {
  DCHECK(!(type.isStructTy() || type.isArrayTy() || type.isVectorTy()));
  std::vector<ValueDecl> ret;
  SizeAndType st = (hint) ? hint.getValue() : AssignSizeAndType(type);
  uint64_t size = SizeConstraintToSize(st.sc);

  auto has_free_regs = false;
  for (size_t i = 0; i < constraints.size(); i++) {

    // Assume for now that the type constraints are uniform across variants.
    // Skip if register is already reserved, or filled, or if types don't match.
    TypeConstraint tc = constraints[i].variants.front().type_constraint;
    if (reserved[i] || IsFilled(i) || !(tc & st.tc)) {
      continue;
    }

    // Skip if we aren't supposed to pack and the register is already partially
    // filled.
    if (!config.can_pack_multiple_values_together && fill[i] != 0) {
      continue;
    }

    has_free_regs = true;

    uint64_t space = RemainingSpace(i);

    // TODO(aty): This might not always be the case and we might have to care
    //            about alignment before we decide to pack a register. But for
    //            right now. We are just packing the register if we can.
    if (size <= space) {
      fill[i] += size;
      if (RemainingSpace(i) == 0) {
        reserved[i] = true;
      }

      const auto &reg_name =
          GetSmallestVariantName(constraints[i].variants, fill[i]);
      if (reg_name.empty()) {
        return llvm::None;
      }
      auto reg = arch->RegisterByName(reg_name);

      auto &vdecl = ret.emplace_back();
      vdecl.reg = reg;
      vdecl.type = &type;
      return ret;
    }
  }

  // On some architectures, we're allowed to split types in two. Often the
  // easiest way to handle this is to convert a basic type into a wide composite
  // type.
  if (has_free_regs && config.type_splitter) {
    if (auto split_type = config.type_splitter(&type);
        split_type && split_type != &type) {
      return TryRegisterAllocate(*split_type);
    }
  }

  return llvm::None;
}

llvm::Optional<std::vector<ValueDecl>>
AllocationState::TryVectorRegisterAllocate(llvm::FixedVectorType &type) {
  std::vector<ValueDecl> ret;
  unsigned vec_size = type.getNumElements();
  const auto elem_type = type.getElementType();

  for (unsigned i = 0; i < vec_size; i++) {

    if (elem_type->isIntegerTy()) {
      auto t = llvm::cast<llvm::IntegerType>(elem_type);

      if (conv->getIdentity() == llvm::CallingConv::X86_64_SysV) {

        // Special case for x86_64
        if (auto inner = ProcessIntVecX86_64SysV(elem_type, vec_size,
                                                 t->getBitWidth())) {
          ret.insert(ret.end(), inner->begin(), inner->end());
        } else {
          return llvm::None;
        }
      } else {

        // Generally, try to pack the registers for a vector.
        const auto prev_pack = config.can_pack_multiple_values_together;
        config.can_pack_multiple_values_together = true;
        if (auto inner = TryRegisterAllocate(*elem_type)) {
          config.can_pack_multiple_values_together = prev_pack;
          ret.insert(ret.end(), inner->begin(), inner->end());
        } else {
          config.can_pack_multiple_values_together = prev_pack;
          return llvm::None;
        }
      }
    } else {
      LOG(FATAL) << "Unhandled vector type: "
                 << remill::LLVMThingToString(&type);
    }
  }

  if (!ret.empty()) {
    return ret;
  }
  return llvm::None;
}

// +----------------------------------------------------------------------+
// | Returning Vectors Through Registers                                  |
// +----------+-----+-----------------------------------------------------+
// |          |     |                     Element Size                    |
// +----------+-----+---------------+-----------+------------+------------+
// |          |     | i64           | i32       |  i16       | i8         |
// +----------+-----+---------------+-----------+------------+------------+
// |  Number  | 2   | xmm0          | xmm0      | xmm0       | xmm0       |
// |    of    +-----+---------------+-----------+------------+------------+
// | Elements | 3   | rax, rdx, rcx | xmm0      | ax, dx, cx | al, dl, cl |
// |          +-----+---------------+-----------+------------+------------+
// |          | 4   | xmm0 xmm1     | xmm0      | xmm0       | RVO        |
// |          +-----+---------------+-----------+------------+------------+
// |          | 5   | RVO           | RVO       | xmm0       | "          |
// |          +-----+---------------+-----------+------------+------------+
// |          | ... | "             | "         | "          | "          |
// |          +-----+---------------+-----------+------------+------------+
// |          | 8   | "             | xmm0 xmm1 | "          | "          |
// |          +-----+---------------+-----------+------------+------------+
// |          | 9   | "             | RVO       | RVO        | "          |
// |          +-----+---------------+-----------+------------+------------+
// |          | ... | "             | "         | "          | "          |
// |          +-----+---------------+-----------+------------+------------+
// |          | 16  | "             | xmm0-3    | xmm0 xmm1  | xmm0       |
// |          +-----+---------------+-----------+------------+------------+
// |          | 17  | "             | RVO       | RVO        | RVO        |
// |          +-----+---------------+-----------+------------+------------+
// |          | ... | "             | "         | "          | "          |
// |          +-----+---------------+-----------+------------+------------+
// |          | 32  | "             | "         | "          | xmm0 xmm1  |
// |          +-----+---------------+-----------+------------+------------+
// |          | ... | "             | "         | "          | "          |
// +----------+-----+---------------+-----------+------------+------------+
// Note: i128 is all RVO for sizes 2+.

llvm::Optional<std::vector<ValueDecl>> AllocationState::ProcessIntVecX86_64SysV(
    llvm::Type *elem_type, unsigned vec_size, unsigned bit_width) {
  const auto prev_pack = config.can_pack_multiple_values_together;
  switch (bit_width) {
    case 64:
      switch (vec_size) {
        case 3: {
          config.can_pack_multiple_values_together = false;
          auto ret = TryRegisterAllocate(*elem_type);
          config.can_pack_multiple_values_together = prev_pack;
          return ret;
        }
        case 2:
        case 4: {
          auto hint = AssignSizeAndType(*elem_type);
          hint.tc = kTypeFloatOrVec;
          config.can_pack_multiple_values_together = true;
          auto ret = TryBasicRegisterAllocate(*elem_type, hint);
          config.can_pack_multiple_values_together = prev_pack;
          return ret;
        }
        default: break;
      }
      break;

    case 32:
      switch (vec_size) {
        case 2:
        case 3:
        case 4:
        case 8:
        case 16: {
          auto hint = AssignSizeAndType(*elem_type);
          hint.tc = kTypeFloatOrVec;
          config.can_pack_multiple_values_together = true;
          auto ret = TryBasicRegisterAllocate(*elem_type, hint);
          config.can_pack_multiple_values_together = prev_pack;
          return ret;
        }
        default: break;
      }
      break;

    case 16:
      switch (vec_size) {
        case 3: {
          config.can_pack_multiple_values_together = false;
          auto ret = TryRegisterAllocate(*elem_type);
          config.can_pack_multiple_values_together = prev_pack;
          return ret;
        }
        case 2:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 16: {
          auto hint = AssignSizeAndType(*elem_type);
          hint.tc = kTypeFloatOrVec;
          config.can_pack_multiple_values_together = true;
          auto ret = TryBasicRegisterAllocate(*elem_type, hint);
          config.can_pack_multiple_values_together = prev_pack;
          return ret;
        }
        default: break;
      }
      break;

    case 8:
      switch (vec_size) {
        case 3: {
          config.can_pack_multiple_values_together = false;
          auto ret = TryRegisterAllocate(*elem_type);
          config.can_pack_multiple_values_together = prev_pack;
          return ret;
        }
        case 2:
        case 16:
        case 32: {
          auto hint = AssignSizeAndType(*elem_type);
          hint.tc = kTypeFloatOrVec;
          config.can_pack_multiple_values_together = true;
          auto ret = TryBasicRegisterAllocate(*elem_type, hint);
          config.can_pack_multiple_values_together = prev_pack;
          return ret;
        }
        default: break;
      }
      break;

    default: LOG(FATAL) << "Invalid bit width: " << bit_width; break;
  }
  return llvm::None;
}

// Coalesce any packed registers into structs that contain the packed types.
// For example, two i32s in a register would become one {i32, 32}.
llvm::Error AllocationState::CoalescePacking(
    const std::vector<ValueDecl> &vector,
    std::vector<anvill::ValueDecl> &packed_values) {

  // Group the decls together by the register that they are allocated to.
  std::vector<std::vector<ValueDecl>> groups(constraints.size());
  for (auto decl : vector) {
    const std::string name = decl.reg->name;
    for (unsigned i = 0; i < constraints.size(); i++) {
      if (constraints[i].ContainsVariant(name)) {
        groups[i].push_back(decl);
        break;
      }
    }
  }

  // Construct structs for each of the registers that have more than one type
  // in them.
  for (unsigned i = 0; i < groups.size(); i++) {
    const auto &g = groups[i];
    if (g.empty()) {
      continue;
    } else if (g.size() == 1) {
      packed_values.push_back(g.front());
      continue;
    }
    std::vector<llvm::Type *> types;
    for (auto const &decl : g) {
      types.push_back(decl.type);
    }

    llvm::ArrayRef<llvm::Type *> ar(types);
    auto st = llvm::StructType::create(*arch->context, ar);
    ValueDecl v;
    const auto size = arch->DataLayout().getTypeAllocSizeInBits(st);
    const auto &reg_name =
        GetSmallestVariantName(constraints[i].variants, size);
    if (reg_name.empty()) {
      return llvm::createStringError(
          std::errc::invalid_argument,
          "Could not find register variant to fit size %u",
          static_cast<unsigned>(size));
    }
    v.reg = arch->RegisterByName(reg_name);
    v.type = st;
    packed_values.push_back(v);
  }

  return llvm::Error::success();
}

}  // namespace anvill
