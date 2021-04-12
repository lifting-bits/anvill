#include <llvm_utils/Utils.h>
#include <glog/logging.h>
#include <remill/BC/Util.h>
#include <llvm/IR/Type.h>
#include <remill/BC/Compat/VectorType.h>

namespace llvm_utils {

std::size_t EstimateSize(const remill::Arch *arch, llvm::Type *type) {
  switch (type->getTypeID()) {
    case llvm::Type::HalfTyID: return 2;
    case llvm::Type::FloatTyID: return 4;
    case llvm::Type::DoubleTyID: return 8;
    case llvm::Type::X86_FP80TyID: return 10;  // Assume no padding.
    case llvm::Type::X86_MMXTyID: return 8;

    case llvm::Type::IntegerTyID:
      return (type->getScalarSizeInBits() + 7u) / 8u;

    case llvm::Type::FP128TyID:
    case llvm::Type::PPC_FP128TyID: return 16;

    // Store a structure by storing the individual elements of the structure.
    //
    // NOTE(pag): We'll assume no padding.
    case llvm::Type::StructTyID: {
      auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
      size_t size = 0;
      for (auto elem_type : struct_type->elements()) {
        size += EstimateSize(arch, elem_type);
      }
      return size;
    }

    // Build up the array store in the same was as we do with structures.
    case llvm::Type::ArrayTyID: {
      auto arr_type = llvm::dyn_cast<llvm::ArrayType>(type);
      const auto num_elems = arr_type->getNumElements();
      const auto elem_type = arr_type->getElementType();
      return num_elems * EstimateSize(arch, elem_type);
    }

    // Write pointers to memory by converting to the correct sized integer,
    // then storing that
    case llvm::Type::PointerTyID: return arch->address_size / 8u;

    // Build up the vector store in the nearly the same was as we do with arrays.
    case llvm::GetFixedVectorTypeId(): {
      auto vec_type = llvm::dyn_cast<llvm::FixedVectorType>(type);
      const auto num_elems = vec_type->getNumElements();
      const auto elem_type = vec_type->getElementType();
      return num_elems * EstimateSize(arch, elem_type);
    }

    case llvm::Type::VoidTyID:
    case llvm::Type::LabelTyID:
    case llvm::Type::MetadataTyID:
    case llvm::Type::TokenTyID:
    case llvm::Type::FunctionTyID:
    default:
      LOG(FATAL) << "Unable to produce IR sequence to store type "
                 << remill::LLVMThingToString(type) << " to memory";
      return 0;
  }
}

}
