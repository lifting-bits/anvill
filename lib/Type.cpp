/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Type.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Metadata.h>

#define ANVILL_USE_WRAPPED_TYPES 0

// clang-format off
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Error.h>
// clang-format on

#include <glog/logging.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>

#include <anvill/ABI.h>
#include <anvill/Utils.h>

#include <sstream>
#include <unordered_map>
#include <vector>

namespace anvill {

class TypeSpecifierImpl {
 public:
  llvm::LLVMContext &context;
  const llvm::DataLayout dl;
  const TypeDictionary type_dict;
  std::unordered_map<llvm::StructType *, size_t> type_to_id;
  std::vector<llvm::StructType *> id_to_type;
  std::unordered_map<void *, llvm::MDNode *> type_to_md;

  inline TypeSpecifierImpl(const TypeDictionary &type_dict_,
                           const llvm::DataLayout &dl_)
      : context(type_dict_.u.named.bool_->getContext()),
        dl(dl_),
        type_dict(type_dict_) {}

  // Translates an llvm::Type to a type that conforms to the spec in
  // TypeSpecification.cpp
  void EncodeType(llvm::Type &type, std::stringstream &ss,
                  EncodingFormat format);

  llvm::MDNode *TypeToMetadata(BaseType type);
  llvm::MDNode *TypeToMetadata(std::shared_ptr<PointerType> type);
  llvm::MDNode *TypeToMetadata(std::shared_ptr<VectorType> type);
  llvm::MDNode *TypeToMetadata(std::shared_ptr<ArrayType> type);
  llvm::MDNode *TypeToMetadata(std::shared_ptr<StructType> type);
  llvm::MDNode *TypeToMetadata(std::shared_ptr<FunctionType> type);
  llvm::MDNode *TypeToMetadata(UnknownType type);
};

// Translates an llvm::Type to a type that conforms to the spec in
// TypeSpecification.cpp
void TypeSpecifierImpl::EncodeType(
    llvm::Type &type, std::stringstream &ss, EncodingFormat format) {
  const auto alpha_num = format == EncodingFormat::kValidSymbolCharsOnly;
  switch (type.getTypeID()) {
    case llvm::Type::VoidTyID: ss << 'v'; break;
    case llvm::Type::HalfTyID: ss << 'e'; break;
    case llvm::Type::FloatTyID: ss << 'f'; break;
    case llvm::Type::DoubleTyID: ss << 'F'; break;
    case llvm::Type::FP128TyID: ss << 'Q'; break;
    case llvm::Type::X86_FP80TyID:
      if (dl.getTypeAllocSize(&type) == 12) {
        ss << 'd';
      } else {
        ss << 'D';
      }
      break;
    case llvm::Type::X86_MMXTyID: ss << 'M'; break;
    case llvm::Type::IntegerTyID: {
      const auto derived = llvm::cast<llvm::IntegerType>(&type);
      constexpr auto sign = false;
      const auto bit_width = derived->getBitWidth();
      if (8u >= bit_width) {
        ss << (sign ? 'b' : 'B');

      } else if (16u >= bit_width) {
        ss << (sign ? 'h' : 'H');

      } else if (32u >= bit_width) {
        ss << (sign ? 'i' : 'I');

      } else if (64u >= bit_width) {
        ss << (sign ? 'l' : 'L');

      } else if (128u >= bit_width) {
        ss << (sign ? 'o' : 'O');

      } else {
        LOG(ERROR)
            << "Could not find an appropriate integer representation for "
            << remill::LLVMThingToString(derived);

        const auto num_bytes = (bit_width + 7u) / 8u;
        ss << (alpha_num ? "_C" : "[") << "Bx" << num_bytes
           << (alpha_num ? "_D" : "]");
      }

      break;
    }

    // There always needs to be at least one parameter type and one
    // return type. Here are some examples:
    //
    //    In C:               Here:
    //    void foo(void)      (vv)
    //    int foo(void)       (vi)
    //    void foo(...)       (&v)
    //    int foo(int, ...)   (i&i)
    //    void foo(int, ...)  (i&v)
    //
    // Not valid: (v...v).
    case llvm::Type::FunctionTyID: {
      auto func_ptr = llvm::cast<llvm::FunctionType>(&type);
      ss << (alpha_num ? "_A" : "(");

      for (llvm::Type *param : func_ptr->params()) {
        EncodeType(*param, ss, format);
      }

      if (func_ptr->isVarArg()) {
        ss << (alpha_num ? "_V" : "&");
      } else if (!func_ptr->getNumParams()) {
        ss << 'v';
      }

      EncodeType(*func_ptr->getReturnType(), ss, format);
      ss << (alpha_num ? "_B" : ")");
      break;
    }

    case llvm::Type::StructTyID: {
      auto struct_ptr = llvm::cast<llvm::StructType>(&type);
      if (struct_ptr == type_dict.u.named.bool_) {
        ss << '?';
      } else if (struct_ptr == type_dict.u.named.char_) {
        ss << 'c';
      } else if (struct_ptr == type_dict.u.named.schar) {
        ss << 's';
      } else if (struct_ptr == type_dict.u.named.uchar) {
        ss << 'S';
      } else if (struct_ptr == type_dict.u.named.int8) {
        ss << 'b';
      } else if (struct_ptr == type_dict.u.named.uint8) {
        ss << 'B';
      } else if (struct_ptr == type_dict.u.named.int16) {
        ss << 'h';
      } else if (struct_ptr == type_dict.u.named.uint16) {
        ss << 'H';
      } else if (struct_ptr == type_dict.u.named.int24) {
        ss << 'w';
      } else if (struct_ptr == type_dict.u.named.uint24) {
        ss << 'W';
      } else if (struct_ptr == type_dict.u.named.int32) {
        ss << 'i';
      } else if (struct_ptr == type_dict.u.named.uint32) {
        ss << 'I';
      } else if (struct_ptr == type_dict.u.named.int64) {
        ss << 'l';
      } else if (struct_ptr == type_dict.u.named.uint64) {
        ss << 'L';
      } else if (struct_ptr == type_dict.u.named.int128) {
        ss << 'o';
      } else if (struct_ptr == type_dict.u.named.uint128) {
        ss << 'O';
      } else if (struct_ptr == type_dict.u.named.float16) {
        ss << 'e';
      } else if (struct_ptr == type_dict.u.named.float32) {
        ss << 'f';
      } else if (struct_ptr == type_dict.u.named.float64) {
        ss << 'F';
      } else if (struct_ptr == type_dict.u.named.float80_12) {
        ss << 'd';
      } else if (struct_ptr == type_dict.u.named.float80_16) {
        ss << 'D';
      } else if (struct_ptr == type_dict.u.named.float128) {
        ss << 'Q';
      } else if (struct_ptr == type_dict.u.named.m64) {
        ss << 'M';
      } else if (struct_ptr == type_dict.u.named.void_) {
        ss << 'v';
      } else if (struct_ptr == type_dict.u.named.padding) {
        ss << 'p';

      // This is an opaque structure; mark it as a void type.
      } else if (struct_ptr->isOpaque()) {
        ss << 'v';

      } else {

        // If we're already serialized this structure type, or if we're inside
        // of the structure type, then use a back reference to avoid infinite
        // recursion.
        if (type_to_id.count(struct_ptr)) {
          ss << (alpha_num ? "_M" : "%") << type_to_id[struct_ptr];

        // We've not yet serialized this structure.
        } else {

          // Start by emitting a new structure ID for this structure and memoizing
          // it to prevent infinite recursion (e.g. on linked lists).
          type_to_id[struct_ptr] = type_to_id.size();
          ss << (alpha_num ? "_X" : "=") << type_to_id[struct_ptr]
             << (alpha_num ? "_E" : "{");

          auto layout = dl.getStructLayout(struct_ptr);
          uint64_t expected_offset = 0u;
          for (unsigned i = 0, num_elems = struct_ptr->getNumElements();
               i < num_elems; ++i) {
            const auto offset = layout->getElementOffset(i);

            // There was some padding before this element.
            if (expected_offset < offset) {
              const auto diff = offset - expected_offset;
              if (diff < 8u) {
                for (auto p = 0u; p < diff; ++p) {
                  ss << 'p';
                }
              } else {
                ss << (alpha_num ? "_C" : "[") << "px" << diff
                   << (alpha_num ? "_D" : "]");
              }

            // TODO(pag): Investigate this possibility. Does this occur for
            //            bitfields?
            } else if (expected_offset > offset) {
              LOG(FATAL) << "TODO?! Maybe bitfields? Structure field offset shenanigans";
            }

            const auto el_ty = struct_ptr->getElementType(i);
            EncodeType(*el_ty, ss, format);
            expected_offset = offset + dl.getTypeStoreSize(el_ty);
          }

          // Padding at the end of the structure. This could be due to alignment.
          const auto aligned_size = dl.getTypeAllocSize(struct_ptr);
          if (expected_offset < aligned_size) {
            const auto diff = aligned_size - expected_offset;
            if (diff < 8u) {
              for (auto p = 0u; p < diff; ++p) {
                ss << 'p';
              }
            } else {
              ss << (alpha_num ? "_C" : "[") << "px" << diff
                 << (alpha_num ? "_D" : "]");
            }
          }
          ss << (alpha_num ? "_F" : "}");
        }
      }
      break;
    }

    case llvm::Type::FixedVectorTyID: {
      const auto vec_ptr = llvm::cast<llvm::FixedVectorType>(&type);
      ss << (alpha_num ? "_G" : "<");
      EncodeType(*vec_ptr->getElementType(), ss, format);
      ss << 'x' << vec_ptr->getNumElements() << (alpha_num ? "_H" : ">");
      break;
    }

    case llvm::Type::ArrayTyID: {
      const auto array_ptr = llvm::cast<llvm::ArrayType>(&type);
      ss << (alpha_num ? "_C" : "[");
      EncodeType(*array_ptr->getElementType(), ss, format);
      ss << 'x' << array_ptr->getNumElements() << (alpha_num ? "_D" : "]");
      break;
    }

    case llvm::Type::PointerTyID: ss << (alpha_num ? "_S" : "*"); break;

    default: {

      // Approximate the type by making an array of bytes of a similar size. If
      // the type has padding due to alignment then we fake a structure and
      // split out the padding from the main data.
      const auto type_size = dl.getTypeStoreSize(&type);
      const auto aligned_size = dl.getTypeAllocSize(&type);
      if (aligned_size > type_size) {
        ss << (alpha_num ? "_E_C" : "{[") << "Bx" << type_size
           << (alpha_num ? "_D_C" : "][") << "Bx" << (aligned_size - type_size)
           << (alpha_num ? "_D_F" : "]}");
      } else {
        ss << (alpha_num ? "_C" : "[") << "Bx" << type_size
           << (alpha_num ? "_D" : "]");
      }
    }
  }
}

llvm::MDNode *TypeSpecifierImpl::TypeToMetadata(BaseType type) {
  auto str = llvm::MDString::get(context, "BaseType");
  auto value = llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context),
                                      static_cast<unsigned>(type));
  return llvm::MDNode::get(context,
                           {str, llvm::ConstantAsMetadata::get(value)});
}

llvm::MDNode *
TypeSpecifierImpl::TypeToMetadata(std::shared_ptr<PointerType> type) {
  auto &node = type_to_md[type.get()];
  if (node) {
    return node;
  }

  auto str = llvm::MDString::get(context, "PointerType");
  auto pointee =
      std::visit([this](auto &&t) { return TypeToMetadata(t); }, type->pointee);
  return llvm::MDNode::get(context, {str, pointee});
}

llvm::MDNode *
TypeSpecifierImpl::TypeToMetadata(std::shared_ptr<VectorType> type) {
  auto &node = type_to_md[type.get()];
  if (node) {
    return node;
  }

  auto str = llvm::MDString::get(context, "VectorType");
  auto base =
      std::visit([this](auto &&t) { return TypeToMetadata(t); }, type->base);
  auto size = llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context),
                                     static_cast<unsigned>(type->size));
  return llvm::MDNode::get(context,
                           {str, base, llvm::ConstantAsMetadata::get(size)});
}

llvm::MDNode *
TypeSpecifierImpl::TypeToMetadata(std::shared_ptr<ArrayType> type) {
  auto &node = type_to_md[type.get()];
  if (node) {
    return node;
  }

  auto str = llvm::MDString::get(context, "ArrayType");
  auto base =
      std::visit([this](auto &&t) { return TypeToMetadata(t); }, type->base);
  auto size = llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context),
                                     static_cast<unsigned>(type->size));
  return llvm::MDNode::get(context,
                           {str, base, llvm::ConstantAsMetadata::get(size)});
}

llvm::MDNode *
TypeSpecifierImpl::TypeToMetadata(std::shared_ptr<StructType> type) {
  auto &node = type_to_md[type.get()];
  if (node) {
    return node;
  }

  auto str = llvm::MDString::get(context, "StructType");
  std::vector<llvm::Metadata *> md;
  md.push_back(str);
  for (auto &member : type->members) {
    md.push_back(
        std::visit([this](auto &&t) { return TypeToMetadata(t); }, member));
  }
  return llvm::MDNode::get(context, md);
}

llvm::MDNode *
TypeSpecifierImpl::TypeToMetadata(std::shared_ptr<FunctionType> type) {
  auto &node = type_to_md[type.get()];
  if (node) {
    return node;
  }

  auto str = llvm::MDString::get(context, "FunctionType");
  std::vector<llvm::Metadata *> md;
  md.push_back(str);
  md.push_back(llvm::ConstantAsMetadata::get(
      llvm::ConstantInt::getBool(context, type->is_variadic)));
  md.push_back(std::visit([this](auto &&t) { return TypeToMetadata(t); },
                          type->return_type));
  for (auto &arg : type->arguments) {
    md.push_back(
        std::visit([this](auto &&t) { return TypeToMetadata(t); }, arg));
  }
  return llvm::MDNode::get(context, md);
}

llvm::MDNode *TypeSpecifierImpl::TypeToMetadata(UnknownType type) {
  auto str = llvm::MDString::get(context, "UnknownType");
  auto size =
      llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context), type.size);
  return llvm::MDNode::get(context, {str, llvm::ConstantAsMetadata::get(size)});
}

namespace {

#if ANVILL_USE_WRAPPED_TYPES

template <typename T>
static llvm::Type *GetOrCreateWrapper(
    llvm::LLVMContext &context, const char *name, T wrapper) {
  std::string type_name = kAnvillNamePrefix + name;
  auto ty = llvm::StructType::getTypeByName(context, type_name);
  if (ty) {
    return ty;
  }

  llvm::Type *elems[] = {wrapper(context)};
  return llvm::StructType::create(context, elems, type_name, true);
}

static llvm::Type *GetOrCreateInt(llvm::LLVMContext &context,
                                  const char *name, unsigned num_bits) {
  return GetOrCreateWrapper(context, name, [=] (llvm::LLVMContext &context_) {
    return llvm::IntegerType::get(context_, num_bits);
  });
}

static llvm::Type *GetOrCreateFloat(llvm::LLVMContext &context,
                                  const char *name, unsigned num_bits) {
  return GetOrCreateWrapper(
      context, name, [=] (llvm::LLVMContext &context_) -> llvm::Type * {
        switch (num_bits) {
          case 16: return llvm::Type::getHalfTy(context_);
          case 32: return llvm::Type::getFloatTy(context_);
          case 64: return llvm::Type::getDoubleTy(context_);
          case 128: return llvm::Type::getFP128Ty(context_);
          default: return nullptr;
        }
      });
}

#endif

}  // namespace

TypeDictionary::TypeDictionary(llvm::LLVMContext &context) {
#if ANVILL_USE_WRAPPED_TYPES
  u.named.bool_ = GetOrCreateInt(context, "bool", 1);
  u.named.char_ = GetOrCreateInt(context, "char", 8);
  u.named.schar = GetOrCreateInt(context, "schar", 8);
  u.named.uchar = GetOrCreateInt(context, "uchar", 8);
  u.named.int8 = GetOrCreateInt(context, "int8", 8);
  u.named.uint8 = GetOrCreateInt(context, "uint8", 8);
  u.named.int16 = GetOrCreateInt(context, "int16", 16);
  u.named.uint16 = GetOrCreateInt(context, "uint16", 16);
  u.named.int32 = GetOrCreateInt(context, "int24", 24);
  u.named.uint32 = GetOrCreateInt(context, "uint24", 24);
  u.named.int32 = GetOrCreateInt(context, "int32", 32);
  u.named.uint32 = GetOrCreateInt(context, "uint32", 32);
  u.named.int64 = GetOrCreateInt(context, "int64", 64);
  u.named.uint64 = GetOrCreateInt(context, "uint64", 64);
  u.named.int128 = GetOrCreateInt(context, "int128", 128);
  u.named.uint128 = GetOrCreateInt(context, "uint128", 128);
  u.named.float16 = GetOrCreateFloat(context, "float16", 16);
  u.named.float32 = GetOrCreateFloat(context, "float32", 32);
  u.named.float64 = GetOrCreateFloat(context, "float64", 64);
  u.named.float80_12 = GetOrCreateWrapper(
      context, "float80_12", [] (llvm::LLVMContext &context_) {
        return llvm::ArrayType::get(llvm::Type::getInt8Ty(context_), 10);
      });
  u.named.float80_16 = GetOrCreateWrapper(
      context, "float80_16", [] (llvm::LLVMContext &context_) {
        return llvm::ArrayType::get(llvm::Type::getInt8Ty(context_), 12);
      });
  u.named.float128 = GetOrCreateFloat(context, "float128", 128);
  u.named.m64 = GetOrCreateWrapper(context, "mmx", [] (llvm::LLVMContext &context_) {
    return llvm::Type::getX86_MMXTy(context_);
  });
  u.named.void_ = GetOrCreateInt(context, "void", 8);
  u.named.padding = GetOrCreateInt(context, "padding", 8);
#else
  u.named.bool_ = llvm::Type::getInt8Ty(context);
  u.named.char_ = llvm::Type::getInt8Ty(context);
  u.named.schar = u.named.char_;
  u.named.uchar = u.named.char_;
  u.named.int8 = u.named.char_;
  u.named.uint8 = u.named.char_;
  u.named.int16 = llvm::Type::getInt16Ty(context);
  u.named.uint16 = u.named.int16;
  u.named.int24 = llvm::Type::getIntNTy(context, 24u);
  u.named.uint24 = u.named.int24;
  u.named.int32 = llvm::Type::getInt32Ty(context);
  u.named.uint32 = u.named.int32;
  u.named.int64 = llvm::Type::getInt64Ty(context);
  u.named.uint64 = u.named.int64;
  u.named.int128 = llvm::Type::getInt128Ty(context);
  u.named.uint128 = u.named.int128;
  u.named.float16 = llvm::Type::getHalfTy(context);
  u.named.float32 = llvm::Type::getFloatTy(context);
  u.named.float64 = llvm::Type::getDoubleTy(context);
  u.named.float80_12 = llvm::Type::getX86_FP80Ty(context);
  u.named.float80_16 = u.named.float80_12;
  u.named.float128 = llvm::Type::getFP128Ty(context);
  u.named.m64 = llvm::Type::getX86_MMXTy(context);
  u.named.void_ = llvm::Type::getVoidTy(context);
  u.named.padding = u.named.char_;
#endif
}

// Returns `true` if `type` is the padding type, or is entirely made up
// of padding bytes (e.g. an array of the padding type).
bool TypeDictionary::IsPadding(llvm::Type *type) const noexcept {
#if ANVILL_USE_WRAPPED_TYPES
  switch (type->getTypeID()) {
    case llvm::Type::StructTyID:
      for (auto elem_type : llvm::dyn_cast<llvm::StructType>(type)->elements()) {
        if (!IsPadding(elem_type)) {
          return false;
        }
      }
      return true;
    case llvm::Type::ArrayTyID: {
      auto elem_type = llvm::dyn_cast<llvm::ArrayType>(type)->getElementType();
      return IsPadding(elem_type);
    }
    case llvm::Type::FixedVectorTyID: {
      auto elem_type = llvm::dyn_cast<llvm::VectorType>(type)->getElementType();
      return IsPadding(elem_type);
    }
    default:
      return type == u.named.padding;
  }
#else
  return false;
#endif
}

TypeTranslator::~TypeTranslator(void) {}

TypeTranslator::TypeTranslator(const TypeDictionary &type_dict,
                             const llvm::DataLayout &dl)
    : impl(std::make_unique<TypeSpecifierImpl>(type_dict, dl)) {}

// Delegating constructor using a module's data layout.
TypeTranslator::TypeTranslator(const TypeDictionary &type_dict,
                               const llvm::Module &module)
    : TypeTranslator(type_dict, module.getDataLayout()) {}

// Delegating constructor using an architecture's data layout.
TypeTranslator::TypeTranslator(const TypeDictionary &type_dict,
                               const remill::Arch *arch)
    : TypeTranslator(type_dict, arch->DataLayout()) {}

TypeTranslator::TypeTranslator(const TypeDictionary &type_dict,
                               const std::unique_ptr<const remill::Arch> &arch)
    : TypeTranslator(type_dict, arch->DataLayout()) {}

// Return the type dictionary for this type specifier.
const TypeDictionary &TypeTranslator::Dictionary(void) const noexcept {
  return impl->type_dict;
}

// Return a reference to the data layout used by this type translator.
const llvm::DataLayout &TypeTranslator::DataLayout(void) const noexcept {
  return impl->dl;
}

// Convert the type `type` to a string encoding. If `alpha_num` is `true`
// then only alpha_numeric characters (and underscores) are used. The
// alpha_numeric representation is always safe to use when appended to
// identifier names.
std::string TypeTranslator::EncodeToString(
    llvm::Type *type, EncodingFormat format) const {
  std::stringstream ss;
  if (type) {
    impl->type_to_id.clear();
    impl->EncodeType(
        *remill::RecontextualizeType(type, impl->context), ss, format);
  }
  return ss.str();
}

llvm::MDNode *TypeTranslator::EncodeToMetadata(TypeSpec spec) const {
  return std::visit([this](auto &&t) { return impl->TypeToMetadata(t); }, spec);
}

// Parse an encoded type string into its represented type.
Result<llvm::Type *, TypeSpecificationError>
TypeTranslator::DecodeFromSpec(TypeSpec spec) const {
  if (std::holds_alternative<BaseType>(spec)) {
    auto base = std::get<BaseType>(spec);
    return impl->type_dict.u.indexed[static_cast<int>(base)];
  }

  if (std::holds_alternative<std::shared_ptr<PointerType>>(spec)) {
    return llvm::PointerType::get(impl->context, 0);
  }

  if (std::holds_alternative<std::shared_ptr<VectorType>>(spec)) {
    auto vec = std::get<std::shared_ptr<VectorType>>(spec);
    auto base = DecodeFromSpec(vec->base);
    if (!base.Succeeded()) {
      return base;
    }
    return llvm::FixedVectorType::get(base.Value(), vec->size);
  }

  if (std::holds_alternative<std::shared_ptr<ArrayType>>(spec)) {
    auto arr = std::get<std::shared_ptr<ArrayType>>(spec);
    auto base = DecodeFromSpec(arr->base);
    if (!base.Succeeded()) {
      return base;
    }
    return llvm::ArrayType::get(base.Value(), arr->size);
  }

  if (std::holds_alternative<std::shared_ptr<StructType>>(spec)) {
    auto strct = std::get<std::shared_ptr<StructType>>(spec);
    std::vector<llvm::Type *> elems;
    for (auto elem : strct->members) {
      auto maybe_elem_ty = DecodeFromSpec(elem);
      if (!maybe_elem_ty.Succeeded()) {
        return maybe_elem_ty;
      }
      elems.push_back(maybe_elem_ty.Value());
    }
    return llvm::StructType::get(impl->context, elems, true);
  }

  if (std::holds_alternative<std::shared_ptr<FunctionType>>(spec)) {
    auto func = std::get<std::shared_ptr<FunctionType>>(spec);
    std::vector<llvm::Type *> args;
    for (auto arg : func->arguments) {
      auto maybe_arg_ty = DecodeFromSpec(arg);
      if (!maybe_arg_ty.Succeeded()) {
        return maybe_arg_ty;
      }
      args.push_back(maybe_arg_ty.Value());
    }
    auto maybe_ret_ty = DecodeFromSpec(func->return_type);
    if (!maybe_ret_ty.Succeeded()) {
      return maybe_ret_ty;
    }

    return llvm::FunctionType::get(maybe_ret_ty.Value(), args,
                                   func->is_variadic);
  }

  if (std::holds_alternative<UnknownType>(spec)) {
    auto unk = std::get<UnknownType>(spec);
    // NOTE(alex): Ghidra seems to list undefined types as having a size of UINT32_MAX.
    // Perhaps a fix belongs in the plugin, but for now let's just keep things moving.
    return llvm::IntegerType::get(impl->context,
                                  unk.size == UINT32_MAX ? 32 : unk.size * 8);
  }

  return TypeSpecificationError{TypeSpecificationError::ErrorCode::InvalidState,
                                "Function fell out of bounds"};
}

namespace {

template <unsigned kSize>
static std::optional<unsigned>
FindTypeInList(llvm::Type *query, llvm::Type *const (&types)[kSize]) {
#if ANVILL_USE_WRAPPED_TYPES
  for (auto i = 0u; i < kSize; ++i) {
    if (types[i] == query) {
      return i;
    }
  }
#endif
  return std::nullopt;
}

}  // namespace

// Convert a value to a specific type.
llvm::Value *TypeDictionary::ConvertValueToType(
    llvm::IRBuilderBase &ir, llvm::Value *src_val,
    llvm::Type *dest_type) const {
  llvm::Type *src_type = src_val->getType();

  if (src_type == dest_type) {
    return src_val;
  }

  auto real_void_type = llvm::Type::getVoidTy(u.named.void_->getContext());
  CHECK_NE(src_type, u.named.void_);
  CHECK_NE(dest_type, u.named.void_);
  CHECK_NE(src_type, real_void_type);
  CHECK_NE(dest_type, real_void_type);

  auto maybe_src_type_index = FindTypeInList(src_type, u.indexed);
  auto maybe_dest_type_index = FindTypeInList(dest_type, u.indexed);

  // Unpack the source type, and then try to build it into the destination
  // type. This dispatches to the next case.
  if (maybe_src_type_index && maybe_dest_type_index) {
//    unsigned indexes[] = {0u};
//    auto dest_val = ir.CreateExtractValue(src_val, indexes);
//    CopyMetadataTo(src_val, dest_val);
//    return ConvertValueToType(ir, dest_val, dest_type);
    LOG(FATAL) << "TODO";
    return nullptr;

  // Pack this type into a destination structure type.
  } else if (!maybe_src_type_index && maybe_dest_type_index) {
    LOG(FATAL) << "TODO";
    return nullptr;

  // Unpack this type from a source structure type.
  } else if (maybe_src_type_index && !maybe_dest_type_index) {
    unsigned indexes[] = {0u};
    auto dest_val = ir.CreateExtractValue(src_val, indexes);
    CopyMetadataTo(src_val, dest_val);
    return AdaptToType(ir, dest_val, dest_type);

  // Raw type adaptation.
  } else {
    return AdaptToType(ir, src_val, dest_type);
  }
}

}  // namespace anvill
