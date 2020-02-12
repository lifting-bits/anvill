#include <anvill/TypePrinter.h>

#include <map>
#include <sstream>

#include <glog/logging.h>

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Type.h>
#include <remill/BC/Util.h>

namespace anvill {

// Translates an llvm::Type to a type that conforms to the spec in
// TypeParser.cpp
void TranslateTypeInternal(llvm::Type &type, std::stringstream &ss,
                           std::map<llvm::Type *, size_t> ids,
                           const llvm::DataLayout &dl) {
  unsigned int id = type.getTypeID();
  switch (id) {
    case llvm::Type::VoidTyID: {
      ss << "v";
      break;
    }
    case llvm::Type::HalfTyID: {
      ss << "e";
      break;
    }
    case llvm::Type::FloatTyID: {
      ss << "f";
      break;
    }
    case llvm::Type::DoubleTyID: {
      ss << "d";
      break;
    }
    case llvm::Type::X86_FP80TyID: {
      ss << "D";
      break;
    }
    case llvm::Type::X86_MMXTyID: {
      ss << "M";
      break;
    }
    case llvm::Type::IntegerTyID: {
      auto derived = llvm::cast<llvm::IntegerType>(type);
      // TODO(aty): Try to distinguish between uint and int.
      // This is a bit complicated because LLVM doesn't make this distinction in
      // its types. It does however, make a distinction between the operations
      // used on signed vs unsigned integers. One idea is to look for these
      // attributes or operations to try to deduce the signedness.
      //
      // For example, we could look for 'div' vs. 'sdiv'.
      //
      // Tracked: https://github.com/lifting-bits/anvill/issues/16
      auto sign = true;
      switch (derived.getBitWidth()) {
        case 8: {
          ss << (sign ? "b" : "B");
          break;
        }
        case 16: {
          ss << (sign ? "h" : "H");
          break;
        }
        case 32: {
          ss << (sign ? "i" : "I");
          break;
        }
        case 64: {
          ss << (sign ? "l" : "L");
          break;
        }
        case 128: {
          ss << (sign ? "o" : "O");
          break;
        }
        default: {
          LOG(ERROR)
              << "Could not find an appropriate integer representation for "
              << remill::LLVMThingToString(&derived);
        }
      }
      break;
    }
    case llvm::Type::FunctionTyID: {
      auto func_ptr = llvm::cast<llvm::FunctionType>(&type);
      ss << "(";
      if (func_ptr->isVarArg()) {
        ss << "&";
      } else {
        for (llvm::Type *param : func_ptr->params()) {
          TranslateTypeInternal(*param, ss, ids, dl);
        }
      }
      TranslateTypeInternal(*func_ptr->getReturnType(), ss, ids, dl);
      ss << ")";
      break;
    }
    case llvm::Type::StructTyID: {
      auto struct_ptr = llvm::cast<llvm::StructType>(&type);
      if (ids.count(&type)) {
        // Do not resolve the same struct more than once when pointer chasing
        ss << "%" << ids[&type];
      } else {
        // Recurse on the elements normally
        ids[&type] = ids.size();
        ss << "=" << ids[&type] << "{";
        for (unsigned i = 0; i < struct_ptr->getNumElements(); i++) {
          TranslateTypeInternal(*struct_ptr->getElementType(i), ss, ids, dl);
        }
        ss << "}";
      }
      break;
    }
    case llvm::Type::ArrayTyID: {
      auto array_ptr = llvm::cast<llvm::ArrayType>(&type);
      ss << "[";
      TranslateTypeInternal(*array_ptr->getElementType(), ss, ids, dl);
      ss << "]";
      break;
    }
    case llvm::Type::PointerTyID: {
      ss << "*";
      auto derived = llvm::dyn_cast<llvm::PointerType>(&type);
      // Get the type of the pointee
      TranslateTypeInternal(*derived->getElementType(), ss, ids, dl);
      break;
    }

    default: {
      // Approximate the type by making an array of bytes of a similar size
      uint64_t type_size = dl.getTypeStoreSize(&type);
      auto arr_type_ptr = llvm::ArrayType::get(
          llvm::IntegerType::get(type.getContext(), 8), type_size / 8);
      TranslateTypeInternal(*arr_type_ptr, ss, ids, dl);
    }
  }
}

std::string TranslateType(llvm::Type &type, const llvm::DataLayout &dl) {
  std::stringstream ss;
  std::map<llvm::Type *, size_t> ids = {};
  TranslateTypeInternal(type, ss, ids, dl);
  return ss.str();
}

}  // namespace anvill