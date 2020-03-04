#include "AllocationState.h"

#include <algorithm>
#include <vector>

#include "Arch/Arch.h"
#include "anvill/Decl.h"

#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <llvm/IR/Attributes.h>

namespace anvill {

// Converts size constraints to reasonable sizes.
uint64_t SizeConstraintToSize(const SizeConstraint &sc) {
  switch (sc) {
    case kMaxBit512:
    case kMinBit512:
      return 512;
    case kMaxBit256:
    case kMinBit256:
      return 256;
    case kMaxBit128:
    case kMinBit128:
      return 128;
    case kMaxBit80:
    case kMinBit80:
      return 80;
    case kMaxBit64:
    case kMinBit64:
      return 64;
    case kMaxBit32:
    case kMinBit32:
      return 32;
    case kMaxBit16:
    case kMinBit16:
      return 16;
    case kMaxBit8:
      return 8;
      // kMinBit8 is a duplicate so it is not included here.
    default: {
      LOG(FATAL) << "Could not handle size constraint";
    }
  }
};

// Get the name of the smallest possible variant that still fits size.
std::string GetSmallestVariantName(
    const std::vector<VariantConstraint> &variants, uint64_t size) {
  for (const auto &vc : variants) {
    if (SizeConstraintToSize(vc.size_constraint) >= size) {
      return vc.register_name;
    }
  }
  LOG(FATAL) << "Could not find a variant to fit size: " << size;
  return "";
}

// Returns whether or not the register at index i is completely filled
bool AllocationState::isFilled(size_t i) { return getRemainingSpace(i) == 0; }

// Gets the remaining space left in register at index i. Assume that the
// largest register variant is at the back of the variants vector.
uint64_t AllocationState::getRemainingSpace(size_t i) {
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
      auto derived = llvm::cast<llvm::IntegerType>(type);
      unsigned int width = derived.getBitWidth();
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
      } else {
        LOG(FATAL) << "Integer too big: "
                   << remill::LLVMThingToString(&derived);
      }
      break;
    }
    case llvm::Type::FloatTyID: {
      type_constraint = kTypeFloat;
      // We automatically know it is 32-bit IEEE floating point type
      size_constraint = kMinBit32;
      break;
    }
    case llvm::Type::DoubleTyID: {
      type_constraint = kTypeFloat;
      // We automatically know it is 64-bit IEEE floating point type
      size_constraint = kMinBit64;
      break;
    }
    case llvm::Type::PointerTyID: {
      type_constraint = kTypeIntegral;
      size_constraint = kMinBit64;
      break;
    }
    case llvm::Type::X86_FP80TyID: {
      type_constraint = kTypeIntegral;
      size_constraint = kMinBit80;
      break;
    }
    case llvm::Type::VectorTyID: {
      type_constraint = kTypeFloatOrVec;
      size_constraint = kMinBit80;
      break;
    }
    default: {
      LOG(FATAL) << "Could not assign type and size constraints for type"
                 << remill::LLVMThingToString(&type);
      // TODO(aty): Handle other types like X86_MMXTyID, etc.
      break;
    }
  }

  return {size_constraint, type_constraint};
}

llvm::Optional<std::vector<ValueDecl>> AllocationState::TryRegisterAllocate(
    llvm::Type &type, bool pack) {
  if (type.isStructTy() || type.isArrayTy() || type.isVectorTy()) {
    return TryCompositeRegisterAllocate(llvm::cast<llvm::CompositeType>(type));
  } else {
    return TryBasicRegisterAllocate(type, llvm::None, pack);
  }
}

llvm::Optional<std::vector<ValueDecl>>
AllocationState::TryCompositeRegisterAllocate(llvm::CompositeType &type) {
  assert(type.isStructTy() || type.isArrayTy() || type.isVectorTy());
  auto ret = std::vector<ValueDecl>();
  if (auto st = llvm::dyn_cast<llvm::StructType>(&type)) {
    for (unsigned i = 0; i < st->getNumElements(); i++) {
      llvm::Type *elem_type = st->getElementType(i);
      if (auto inner = TryRegisterAllocate(*elem_type, true)) {
        ret.insert(ret.end(), inner->begin(), inner->end());
      } else {
        return llvm::None;
      }
    }
  } else if (auto arr = llvm::dyn_cast<llvm::ArrayType>(&type)) {
    // Arrays must be of a uniform type
    llvm::Type *elem_type = arr->getArrayElementType();
    for (unsigned i = 0; i < arr->getNumElements(); i++) {
      if (auto inner = TryRegisterAllocate(*elem_type, true)) {
        ret.insert(ret.end(), inner->begin(), inner->end());
      } else {
        return llvm::None;
      }
    }
  } else if (auto vec = llvm::dyn_cast<llvm::VectorType>(&type)) {
    if (auto inner = TryVectorRegisterAllocate(*vec)) {
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
                                          llvm::Optional<SizeAndType> hint,
                                          bool pack) {
  assert(!(type.isStructTy() || type.isArrayTy() || type.isVectorTy()));
  auto ret = std::vector<ValueDecl>();
  SizeAndType st = (hint) ? hint.getValue() : AssignSizeAndType(type);
  uint64_t size = SizeConstraintToSize(st.sc);

  for (size_t i = 0; i < constraints.size(); i++) {
    // Assume for now that the type constraints are uniform across variants.
    // Skip if register is already reserved, or filled, or if types don't match.
    TypeConstraint tc = constraints[i].variants.front().type_constraint;
    if (reserved[i] || isFilled(i) || !(tc & st.tc)) {
      continue;
    }

    // Skip if we aren't supposed to pack and the register is already partially
    // filled.
    if (!pack && fill[i] != 0) {
      continue;
    }

    uint64_t space = getRemainingSpace(i);

    // TODO:(aty) This might not always be the case and we might have to care
    // about alignment before we decide to pack a register. But for right now
    // We are just packing the register if we can.
    if (size <= space) {
      fill[i] += size;
      if (getRemainingSpace(i) == 0) {
        reserved[i] = true;
      }
      auto reg = arch->RegisterByName(
          GetSmallestVariantName(constraints[i].variants, fill[i]));
      ValueDecl vdecl = {};
      vdecl.reg = reg;
      vdecl.type = &type;
      ret.push_back(vdecl);
      return ret;
    }
  }

  return llvm::None;
}

llvm::Optional<std::vector<ValueDecl>>
AllocationState::TryVectorRegisterAllocate(llvm::VectorType &type) {
  auto ret = std::vector<ValueDecl>();
  unsigned vec_size = type.getVectorNumElements();

  for (unsigned i = 0; i < vec_size; i++) {
    auto elem_type = type.getVectorElementType();

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
        // Generally, try to pack the registers for a vector
        if (auto inner = TryRegisterAllocate(*elem_type, true)) {
          ret.insert(ret.end(), inner->begin(), inner->end());
        } else {
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
  switch (bit_width) {
    case 64: {
      switch (vec_size) {
        case 3: {
          return TryRegisterAllocate(*elem_type, false);
        }
        case 2:
        case 4: {
          auto hint = AssignSizeAndType(*elem_type);
          hint.tc = kTypeFloatOrVec;
          return TryBasicRegisterAllocate(*elem_type, hint, true);
        }
        default: {
          return llvm::None;
        }
      }
    }
    case 32: {
      switch (vec_size) {
        case 2:
        case 3:
        case 4:
        case 8:
        case 16: {
          auto hint = AssignSizeAndType(*elem_type);
          hint.tc = kTypeFloatOrVec;
          return TryBasicRegisterAllocate(*elem_type, hint, true);
        }
        default: {
          return llvm::None;
        }
      }
    }
    case 16: {
      switch (vec_size) {
        case 3: {
          return TryRegisterAllocate(*elem_type, false);
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
          return TryBasicRegisterAllocate(*elem_type, hint, true);
        }
        default: {
          return llvm::None;
        }
      }
    }
    case 8: {
      switch (vec_size) {
        case 3: {
          return TryRegisterAllocate(*elem_type, false);
        }
        case 2:
        case 16:
        case 32: {
          auto hint = AssignSizeAndType(*elem_type);
          hint.tc = kTypeFloatOrVec;
          return TryBasicRegisterAllocate(*elem_type, hint, true);
        }
        default: {
          return llvm::None;
        }
      }
    }
    default: {
      LOG(FATAL) << "Invalid bit width: " << bit_width;
    }
  }
  return llvm::None;
}

// Coalesce any packed registers into structs that contain the packed types.
// For example, two i32s in a register would become one {i32, 32}.
std::vector<ValueDecl> AllocationState::CoalescePacking(
    const std::vector<ValueDecl> &vector) {
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
  std::vector<ValueDecl> ret;
  for (unsigned i = 0; i < groups.size(); i++) {
    const auto &g = groups[i];
    if (g.empty()) {
      continue;
    }
    if (g.size() == 1) {
      ret.push_back(g.front());
      continue;
    }
    std::vector<llvm::Type *> types;
    for (auto const &decl : g) {
      types.push_back(decl.type);
    }
    llvm::ArrayRef<llvm::Type *> ar(types);
    auto st = llvm::StructType::create(*arch->context, ar);
    ValueDecl v;
    v.reg = arch->RegisterByName(
        GetSmallestVariantName(constraints[i].variants,
                               arch->DataLayout().getTypeAllocSizeInBits(st)));
    v.type = st;
    ret.push_back(v);
  }

  return ret;
}

}  // namespace anvill