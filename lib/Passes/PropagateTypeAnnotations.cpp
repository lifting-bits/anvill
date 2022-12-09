/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Passes/PropagateTypeAnnotations.h>
#include <anvill/Type.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Type.h>

namespace anvill {
struct PropagateTypeAnnotations::Impl {
  StructMap &structs;

  llvm::Type *MDToType(llvm::LLVMContext &context, llvm::MDNode *md);
  llvm::StructType *MDToStruct(llvm::LLVMContext &context, llvm::MDNode *md);

  Impl(StructMap &structs) : structs(structs) {}
};

llvm::Type *PropagateTypeAnnotations::Impl::MDToType(llvm::LLVMContext &context,
                                                     llvm::MDNode *md) {
  auto tag = llvm::cast<llvm::MDString>(md->getOperand(0).get());
  auto tag_string = tag->getString();
  if (tag_string == "BaseType") {
    auto kind_const =
        llvm::cast<llvm::ConstantAsMetadata>(md->getOperand(1).get());
    auto kind_int = llvm::cast<llvm::ConstantInt>(kind_const->getValue());
    auto kind = static_cast<BaseType>(kind_int->getZExtValue());

    switch (kind) {
      case BaseType::Bool:
      case BaseType::Char:
      case BaseType::SignedChar:
      case BaseType::UnsignedChar:
      case BaseType::Int8:
      case BaseType::UInt8:
      case BaseType::Padding: return llvm::Type::getInt8Ty(context);

      case BaseType::Int16:
      case BaseType::UInt16: return llvm::Type::getInt16Ty(context);

      case BaseType::Int24:
      case BaseType::UInt24:
      case BaseType::Int32:
      case BaseType::UInt32: return llvm::Type::getInt32Ty(context);

      case BaseType::Int64:
      case BaseType::UInt64: return llvm::Type::getInt64Ty(context);

      case BaseType::Int128:
      case BaseType::UInt128: return llvm::Type::getInt128Ty(context);

      case BaseType::Float16: return llvm::Type::getHalfTy(context);
      case BaseType::Float32: return llvm::Type::getFloatTy(context);
      case BaseType::Float64: return llvm::Type::getDoubleTy(context);
      case BaseType::Float80: return llvm::Type::getX86_FP80Ty(context);
      case BaseType::Float128: return llvm::Type::getFP128Ty(context);
      case BaseType::MMX64: return llvm::Type::getX86_MMXTy(context);

      case BaseType::Void: return llvm::Type::getVoidTy(context);

      default: return nullptr;
    }
  } else if (tag_string == "PointerType") {
    return llvm::PointerType::get(context, 0);
  } else if (tag_string == "VectorType") {
    auto elem =
        MDToType(context, llvm::cast<llvm::MDNode>(md->getOperand(1).get()));
    auto size_const =
        llvm::cast<llvm::ConstantAsMetadata>(md->getOperand(2).get());
    auto size_int = llvm::cast<llvm::ConstantInt>(size_const->getValue());
    return llvm::VectorType::get(elem, size_int->getZExtValue(), false);
  } else if (tag_string == "ArrayType") {
    auto elem =
        MDToType(context, llvm::cast<llvm::MDNode>(md->getOperand(1).get()));
    auto size_const =
        llvm::cast<llvm::ConstantAsMetadata>(md->getOperand(2).get());
    auto size_int = llvm::cast<llvm::ConstantInt>(size_const->getValue());
    return llvm::ArrayType::get(elem, size_int->getZExtValue());
  } else if (tag_string == "StructType") {
    return MDToStruct(context, md);
  } else if (tag_string == "FunctionType") {
    // TODO(frabert)
    return nullptr;
  } else if (tag_string == "UnknownType") {
    auto size_const =
        llvm::cast<llvm::ConstantAsMetadata>(md->getOperand(1).get());
    auto size_int = llvm::cast<llvm::ConstantInt>(size_const->getValue());
    return llvm::Type::getIntNTy(context, size_int->getZExtValue() * 8);
  }
  return nullptr;
}

llvm::StructType *
PropagateTypeAnnotations::Impl::MDToStruct(llvm::LLVMContext &context,
                                           llvm::MDNode *md) {
  auto &struct_ = structs[md];
  if (struct_) {
    return struct_;
  }

  std::vector<llvm::Type *> elems;
  for (unsigned i = 1; i < md->getNumOperands(); ++i) {
    elems.push_back(
        MDToType(context, llvm::cast<llvm::MDNode>(md->getOperand(i).get())));
  }
  struct_ = llvm::StructType::get(context, elems, true);

  return struct_;
}

PropagateTypeAnnotations::PropagateTypeAnnotations(StructMap &structs)
    : impl(std::make_unique<Impl>(structs)) {}

llvm::StringRef PropagateTypeAnnotations::name() {
  return "PropagateTypeAnnotations";
}

llvm::PreservedAnalyses
PropagateTypeAnnotations::run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &fam) {

  return llvm::PreservedAnalyses::all();
}
}  // namespace anvill