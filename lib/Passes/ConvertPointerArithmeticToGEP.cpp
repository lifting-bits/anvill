/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Declarations.h>
#include <anvill/Passes/ConvertPointerArithmeticToGEP.h>
#include <anvill/Type.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/Casting.h>

#include <memory>
#include <unordered_map>
#include <variant>
#include <vector>

namespace anvill {
struct ConvertPointerArithmeticToGEP::Impl {
  const BasicBlockContexts &contexts;
  TypeMap &types;
  StructMap &structs;
  MDMap &md;

  TypeSpec MDToTypeSpec(llvm::MDNode *md);
  std::optional<TypeSpec> GetTypeInfo(llvm::Value *val);

  llvm::Type *TypeSpecToType(llvm::LLVMContext &context, BaseType t);
  llvm::PointerType *TypeSpecToType(llvm::LLVMContext &context,
                                    std::shared_ptr<PointerType> t);
  llvm::ArrayType *TypeSpecToType(llvm::LLVMContext &context,
                                  std::shared_ptr<ArrayType> t);
  llvm::FixedVectorType *TypeSpecToType(llvm::LLVMContext &context,
                                        std::shared_ptr<VectorType> t);
  llvm::StructType *TypeSpecToType(llvm::LLVMContext &context,
                                   std::shared_ptr<StructType> t);
  llvm::FunctionType *TypeSpecToType(llvm::LLVMContext &context,
                                     std::shared_ptr<FunctionType> t);
  llvm::IntegerType *TypeSpecToType(llvm::LLVMContext &context, UnknownType t);
  llvm::Type *TypeSpecToType(llvm::LLVMContext &context, TypeSpec type);

  llvm::MDNode *TypeSpecToMD(llvm::LLVMContext &context, BaseType t);
  llvm::MDNode *TypeSpecToMD(llvm::LLVMContext &context,
                             std::shared_ptr<PointerType> t);
  llvm::MDNode *TypeSpecToMD(llvm::LLVMContext &context,
                             std::shared_ptr<ArrayType> t);
  llvm::MDNode *TypeSpecToMD(llvm::LLVMContext &context,
                             std::shared_ptr<VectorType> t);
  llvm::MDNode *TypeSpecToMD(llvm::LLVMContext &context,
                             std::shared_ptr<StructType> t);
  llvm::MDNode *TypeSpecToMD(llvm::LLVMContext &context,
                             std::shared_ptr<FunctionType> t);
  llvm::MDNode *TypeSpecToMD(llvm::LLVMContext &context, UnknownType t);
  llvm::MDNode *TypeSpecToMD(llvm::LLVMContext &context, TypeSpec type);

  bool ConvertLoadInt(llvm::Function &f);
  bool FoldPtrAdd(llvm::Function &f);
  bool FoldScaledIndex(llvm::Function &f);

  Impl(const BasicBlockContexts &contexts, TypeMap &types, StructMap &structs,
       MDMap &md)
      : contexts(contexts),
        types(types),
        structs(structs),
        md(md) {}
};


llvm::Type *
ConvertPointerArithmeticToGEP::Impl::TypeSpecToType(llvm::LLVMContext &context,
                                                    BaseType t) {
  switch (t) {
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
    case BaseType::UInt24: return llvm::Type::getIntNTy(context, 24);

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
}

llvm::PointerType *ConvertPointerArithmeticToGEP::Impl::TypeSpecToType(
    llvm::LLVMContext &context, std::shared_ptr<PointerType> t) {
  return llvm::PointerType::get(context, 0);
}

llvm::ArrayType *ConvertPointerArithmeticToGEP::Impl::TypeSpecToType(
    llvm::LLVMContext &context, std::shared_ptr<ArrayType> t) {
  return llvm::ArrayType::get(TypeSpecToType(context, t->base), t->size);
}

llvm::FixedVectorType *ConvertPointerArithmeticToGEP::Impl::TypeSpecToType(
    llvm::LLVMContext &context, std::shared_ptr<VectorType> t) {
  return llvm::FixedVectorType::get(TypeSpecToType(context, t->base), t->size);
}

llvm::StructType *ConvertPointerArithmeticToGEP::Impl::TypeSpecToType(
    llvm::LLVMContext &context, std::shared_ptr<StructType> t) {
  auto &type = structs[t.get()];
  if (type) {
    return type;
  }

  std::vector<llvm::Type *> members;
  for (auto member : t->members) {
    members.push_back(TypeSpecToType(context, member));
  }
  type = llvm::StructType::get(context, members, /*isPacked=*/true);
  return type;
}

llvm::FunctionType *ConvertPointerArithmeticToGEP::Impl::TypeSpecToType(
    llvm::LLVMContext &context, std::shared_ptr<FunctionType> t) {
  std::vector<llvm::Type *> args;
  for (auto arg : t->arguments) {
    args.push_back(TypeSpecToType(context, arg));
  }
  return llvm::FunctionType::get(TypeSpecToType(context, t->return_type), args,
                                 t->is_variadic);
}

llvm::IntegerType *
ConvertPointerArithmeticToGEP::Impl::TypeSpecToType(llvm::LLVMContext &context,
                                                    UnknownType t) {
  return llvm::Type::getIntNTy(context, t.size * 8);
}

llvm::Type *
ConvertPointerArithmeticToGEP::Impl::TypeSpecToType(llvm::LLVMContext &context,
                                                    TypeSpec type) {
  return std::visit(
      [this, &context](auto &&t) {
        return static_cast<llvm::Type *>(TypeSpecToType(context, t));
      },
      type);
}

TypeSpec ConvertPointerArithmeticToGEP::Impl::MDToTypeSpec(llvm::MDNode *md) {
  if (types.count(md)) {
    return types[md];
  }

  auto &type = types[md];
  auto tag = llvm::cast<llvm::MDString>(md->getOperand(0).get());
  auto tag_string = tag->getString();
  if (tag_string == "BaseType") {
    auto kind_const =
        llvm::cast<llvm::ConstantAsMetadata>(md->getOperand(1).get());
    auto kind_int = llvm::cast<llvm::ConstantInt>(kind_const->getValue());
    auto kind = static_cast<BaseType>(kind_int->getZExtValue());

    type = kind;
  } else if (tag_string == "PointerType") {
    auto pointee =
        MDToTypeSpec(llvm::cast<llvm::MDNode>(md->getOperand(1).get()));
    type = std::make_shared<PointerType>(pointee, false);
  } else if (tag_string == "VectorType") {
    auto elem = MDToTypeSpec(llvm::cast<llvm::MDNode>(md->getOperand(1).get()));
    auto size_const =
        llvm::cast<llvm::ConstantAsMetadata>(md->getOperand(2).get());
    auto size_int = llvm::cast<llvm::ConstantInt>(size_const->getValue());
    type = std::make_shared<VectorType>(elem, size_int->getZExtValue());
  } else if (tag_string == "ArrayType") {
    auto elem = MDToTypeSpec(llvm::cast<llvm::MDNode>(md->getOperand(1).get()));
    auto size_const =
        llvm::cast<llvm::ConstantAsMetadata>(md->getOperand(2).get());
    auto size_int = llvm::cast<llvm::ConstantInt>(size_const->getValue());
    type = std::make_shared<ArrayType>(elem, size_int->getZExtValue());
  } else if (tag_string == "StructType") {
    auto struct_ = std::make_shared<StructType>();
    for (unsigned i = 1; i < md->getNumOperands(); ++i) {
      struct_->members.push_back(
          MDToTypeSpec(llvm::cast<llvm::MDNode>(md->getOperand(i).get())));
    }
    type = struct_;
  } else if (tag_string == "FunctionType") {
    // TODO(frabert)
  } else if (tag_string == "UnknownType") {
    auto size_const =
        llvm::cast<llvm::ConstantAsMetadata>(md->getOperand(1).get());
    auto size_int = llvm::cast<llvm::ConstantInt>(size_const->getValue());
    type = UnknownType{static_cast<unsigned>(size_int->getZExtValue())};
  }
  return type;
}

std::optional<TypeSpec>
ConvertPointerArithmeticToGEP::Impl::GetTypeInfo(llvm::Value *val) {
  llvm::MDNode *md = nullptr;
  if (auto gvar = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    md = gvar->getMetadata("anvill.type");
  } else if (auto ptr_insn = llvm::dyn_cast<llvm::Instruction>(val)) {
    md = ptr_insn->getMetadata("anvill.type");
  }

  if (!md) {
    return {};
  }

  return MDToTypeSpec(md);
}

llvm::MDNode *
ConvertPointerArithmeticToGEP::Impl::TypeSpecToMD(llvm::LLVMContext &context,
                                                  BaseType t) {
  auto str = llvm::MDString::get(context, "BaseType");
  auto value = llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context),
                                      static_cast<unsigned>(t));
  return llvm::MDNode::get(context,
                           {str, llvm::ConstantAsMetadata::get(value)});
}

llvm::MDNode *ConvertPointerArithmeticToGEP::Impl::TypeSpecToMD(
    llvm::LLVMContext &context, std::shared_ptr<PointerType> t) {
  auto str = llvm::MDString::get(context, "PointerType");
  return llvm::MDNode::get(context, {str, TypeSpecToMD(context, t->pointee)});
}

llvm::MDNode *ConvertPointerArithmeticToGEP::Impl::TypeSpecToMD(
    llvm::LLVMContext &context, std::shared_ptr<ArrayType> t) {
  auto str = llvm::MDString::get(context, "ArrayType");
  auto size =
      llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context), t->size);
  return llvm::MDNode::get(context, {str, TypeSpecToMD(context, t->base),
                                     llvm::ConstantAsMetadata::get(size)});
}

llvm::MDNode *ConvertPointerArithmeticToGEP::Impl::TypeSpecToMD(
    llvm::LLVMContext &context, std::shared_ptr<VectorType> t) {
  auto str = llvm::MDString::get(context, "VectorType");
  auto size =
      llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context), t->size);
  return llvm::MDNode::get(context, {str, TypeSpecToMD(context, t->base),
                                     llvm::ConstantAsMetadata::get(size)});
}

llvm::MDNode *ConvertPointerArithmeticToGEP::Impl::TypeSpecToMD(
    llvm::LLVMContext &context, std::shared_ptr<StructType> t) {
  auto str = llvm::MDString::get(context, "StructType");
  std::vector<llvm::Metadata *> members;
  members.push_back(str);
  for (auto member : t->members) {
    members.push_back(TypeSpecToMD(context, member));
  }
  return llvm::MDNode::get(context, members);
}

llvm::MDNode *ConvertPointerArithmeticToGEP::Impl::TypeSpecToMD(
    llvm::LLVMContext &context, std::shared_ptr<FunctionType> t) {
  return nullptr;
}

llvm::MDNode *
ConvertPointerArithmeticToGEP::Impl::TypeSpecToMD(llvm::LLVMContext &context,
                                                  UnknownType t) {
  auto str = llvm::MDString::get(context, "UnknownType");
  auto size = llvm::ConstantInt::get(llvm::IntegerType::getInt32Ty(context),
                                     static_cast<unsigned>(t.size));
  return llvm::MDNode::get(context, {str, llvm::ConstantAsMetadata::get(size)});
}

llvm::MDNode *
ConvertPointerArithmeticToGEP::Impl::TypeSpecToMD(llvm::LLVMContext &context,
                                                  TypeSpec type) {
  return std::visit(
      [this, &context](auto &&t) { return TypeSpecToMD(context, t); }, type);
}

ConvertPointerArithmeticToGEP::ConvertPointerArithmeticToGEP(
    const BasicBlockContexts &contexts, TypeMap &types, StructMap &structs,
    MDMap &md)
    : BasicBlockPass(contexts),
      impl(std::make_unique<Impl>(contexts, types, structs, md)) {}

ConvertPointerArithmeticToGEP::ConvertPointerArithmeticToGEP(
    const ConvertPointerArithmeticToGEP &pass)
    : BasicBlockPass(pass.impl->contexts),
      impl(std::make_unique<Impl>(pass.impl->contexts, pass.impl->types,
                                  pass.impl->structs, pass.impl->md)) {}


ConvertPointerArithmeticToGEP::~ConvertPointerArithmeticToGEP() = default;

llvm::StringRef ConvertPointerArithmeticToGEP::name() {
  return "ConvertPointerArithmeticToGEP";
}

// Finds `(load i64, P)` and converts it to `(ptrtoint (load ptr, P))`
bool ConvertPointerArithmeticToGEP::Impl::ConvertLoadInt(llvm::Function &f) {
  using namespace llvm::PatternMatch;
  llvm::Value *ptr;
  auto &context = f.getContext();
  auto &dl = f.getParent()->getDataLayout();
  auto pat = m_Load(m_Value(ptr));
  for (auto &insn : llvm::instructions(f)) {
    if (!match(&insn, pat)) {
      continue;
    }

    auto old_load = llvm::cast<llvm::LoadInst>(&insn);
    auto load_ty = old_load->getType();
    if (load_ty != llvm::Type::getIntNTy(context, dl.getPointerSizeInBits())) {
      continue;
    }

    auto maybe_type_info = GetTypeInfo(ptr);
    if (!maybe_type_info) {
      continue;
    }
    auto type_info = *maybe_type_info;

    if (auto gvar = llvm::dyn_cast<llvm::GlobalVariable>(ptr)) {
      if (!std::holds_alternative<std::shared_ptr<PointerType>>(type_info)) {
        continue;
      }

      auto ptr_type = std::get<std::shared_ptr<PointerType>>(type_info);
      auto new_load = new llvm::LoadInst(llvm::PointerType::get(context, 0),
                                         ptr, "", &insn);
      new_load->setMetadata("anvill.type", TypeSpecToMD(context, type_info));
      auto ptrtoint = new llvm::PtrToIntInst(new_load, load_ty, "", &insn);
      insn.replaceAllUsesWith(ptrtoint);

      return true;
    }

    if (auto ptr_insn = llvm::dyn_cast<llvm::Instruction>(ptr)) {
      if (!std::holds_alternative<std::shared_ptr<PointerType>>(type_info)) {
        continue;
      }

      auto ptr_type = std::get<std::shared_ptr<PointerType>>(type_info);
      if (!std::holds_alternative<std::shared_ptr<PointerType>>(
              ptr_type->pointee)) {
        continue;
      }

      auto new_load = new llvm::LoadInst(llvm::PointerType::get(context, 0),
                                         ptr, "", &insn);
      new_load->setMetadata("anvill.type",
                            TypeSpecToMD(context, ptr_type->pointee));
      auto ptrtoint = new llvm::PtrToIntInst(new_load, load_ty, "", &insn);
      insn.replaceAllUsesWith(ptrtoint);

      return true;
    }
  }

  return false;
}

// Finds `(add (ptrtoint P), A)` and tries to convert to `(ptrtoint (gep ...))`
bool ConvertPointerArithmeticToGEP::Impl::FoldPtrAdd(llvm::Function &f) {
  using namespace llvm::PatternMatch;
  llvm::Value *ptr;
  llvm::ConstantInt *offset_const;
  auto &context = f.getContext();
  auto &dl = f.getParent()->getDataLayout();
  auto pat = m_Add(m_PtrToInt(m_Value(ptr)), m_ConstantInt(offset_const));
  for (auto &insn : llvm::instructions(f)) {
    if (!match(&insn, pat)) {
      continue;
    }

    auto maybe_ptr_type = GetTypeInfo(ptr);
    if (!maybe_ptr_type.has_value()) {
      continue;
    }

    if (!std::holds_alternative<std::shared_ptr<PointerType>>(
            *maybe_ptr_type)) {
      continue;
    }

    auto pointee_spec =
        std::get<std::shared_ptr<PointerType>>(*maybe_ptr_type)->pointee;
    auto pointee_type = TypeSpecToType(context, pointee_spec);

    auto offset = offset_const->getZExtValue();
    std::vector<unsigned> indices;

    auto cur_spec = pointee_spec;
    auto cur_type = pointee_type;
    if (!cur_type->isSized()) {
      continue;
    }

    {
      auto cur_size = dl.getTypeSizeInBits(cur_type) / 8;
      auto index = offset / cur_size;
      indices.push_back(index);
      offset = offset % cur_size;
    }
    while (offset != 0) {
      if (std::holds_alternative<std::shared_ptr<StructType>>(cur_spec)) {
        auto struct_spec = std::get<std::shared_ptr<StructType>>(cur_spec);
        auto struct_type = llvm::cast<llvm::StructType>(cur_type);

        auto layout = dl.getStructLayout(struct_type);
        auto index = layout->getElementContainingOffset(offset);
        indices.push_back(index);

        cur_spec = struct_spec->members[index];
        cur_type = struct_type->getElementType(index);
        offset -= layout->getElementOffset(index);
      } else if (std::holds_alternative<std::shared_ptr<ArrayType>>(cur_spec)) {
        auto arr_spec = std::get<std::shared_ptr<ArrayType>>(cur_spec);
        auto arr_type = llvm::cast<llvm::ArrayType>(cur_type);

        auto elem_size =
            dl.getTypeSizeInBits(arr_type->getArrayElementType()) / 8;
        auto index = offset / elem_size;
        indices.push_back(index);

        cur_spec = arr_spec->base;
        cur_type = arr_type->getArrayElementType();
        offset -= index * elem_size;
      } else if (std::holds_alternative<std::shared_ptr<VectorType>>(
                     cur_spec)) {
        auto vec_spec = std::get<std::shared_ptr<VectorType>>(cur_spec);
        auto vec_type = llvm::cast<llvm::VectorType>(cur_type);

        auto elem_size = dl.getTypeSizeInBits(vec_type->getElementType()) / 8;
        auto index = offset / elem_size;
        indices.push_back(index);

        cur_spec = vec_spec->base;
        cur_type = vec_type->getElementType();
        offset -= index * elem_size;
      } else {
        break;
      }
    }

    if (offset != 0) {
      continue;
    }

    std::vector<llvm::Value *> indices_values;
    auto i32 = llvm::Type::getInt32Ty(context);
    for (auto i : indices) {
      indices_values.push_back(llvm::ConstantInt::get(i32, i));
    }
    auto next_insn = insn.getNextNonDebugInstruction();
    auto gep = llvm::GetElementPtrInst::Create(pointee_type, ptr,
                                               indices_values, "", next_insn);
    gep->setMetadata("anvill.type", TypeSpecToMD(context, cur_spec));
    auto ptrtoint = new llvm::PtrToIntInst(
        gep, llvm::Type::getIntNTy(context, dl.getPointerSizeInBits()), "",
        next_insn);
    insn.replaceAllUsesWith(ptrtoint);

    return true;
  }

  return false;
}

// Convert `(add (ptrtoint P), (shl I, S))` to `(ptrtoint (gep P, I))`
bool ConvertPointerArithmeticToGEP::Impl::FoldScaledIndex(llvm::Function &f) {
  using namespace llvm::PatternMatch;
  llvm::Value *ptr;
  llvm::Value *base;
  llvm::ConstantInt *shift_const;
  auto &context = f.getContext();
  auto &dl = f.getParent()->getDataLayout();
  auto patL = m_Add(m_PtrToInt(m_Value(ptr)),
                    m_Shl(m_Value(base), m_ConstantInt(shift_const)));
  auto patR = m_Add(m_Shl(m_Value(base), m_ConstantInt(shift_const)),
                    m_PtrToInt(m_Value(ptr)));
  auto ptrint_ty = llvm::Type::getIntNTy(context, dl.getPointerSizeInBits());
  for (auto &insn : llvm::instructions(f)) {
    if (!match(&insn, patL) && !match(&insn, patR)) {
      continue;
    }

    auto maybe_type_info = GetTypeInfo(ptr);
    if (!maybe_type_info.has_value()) {
      continue;
    }

    auto scale = 1ull << shift_const->getZExtValue();
    auto type_info = *maybe_type_info;

    auto next_insn = insn.getNextNonDebugInstruction();

    if (std::holds_alternative<std::shared_ptr<ArrayType>>(type_info)) {
      auto array_spec = std::get<std::shared_ptr<ArrayType>>(type_info);
      auto array_type = TypeSpecToType(context, array_spec);
      auto elem_size =
          dl.getTypeSizeInBits(array_type->getArrayElementType()) / 8;
      if (scale != elem_size) {
        continue;
      }

      auto gep = llvm::GetElementPtrInst::Create(
          array_type, ptr, {llvm::ConstantInt::get(ptrint_ty, 0), base}, "",
          next_insn);
      gep->setMetadata("anvill.type", TypeSpecToMD(context, array_spec->base));
      auto ptrtoint = new llvm::PtrToIntInst(gep, ptrint_ty, "", next_insn);
      insn.replaceAllUsesWith(ptrtoint);
      return true;
    }

    if (std::holds_alternative<std::shared_ptr<VectorType>>(type_info)) {
      auto vector_spec = std::get<std::shared_ptr<VectorType>>(type_info);
      auto vector_type = TypeSpecToType(context, vector_spec);
      auto elem_size = dl.getTypeSizeInBits(vector_type->getElementType()) / 8;
      if (scale != elem_size) {
        continue;
      }

      auto gep = llvm::GetElementPtrInst::Create(
          vector_type, ptr, {llvm::ConstantInt::get(ptrint_ty, 0), base}, "",
          next_insn);
      gep->setMetadata("anvill.type", TypeSpecToMD(context, vector_spec->base));
      auto ptrtoint = new llvm::PtrToIntInst(gep, ptrint_ty, "", next_insn);
      insn.replaceAllUsesWith(ptrtoint);
      return true;
    }
  }
  return false;
}

llvm::PreservedAnalyses ConvertPointerArithmeticToGEP::runOnBasicBlockFunction(
    llvm::Function &function, llvm::FunctionAnalysisManager &fam,
    const anvill::BasicBlockContext &, const FunctionDecl &) {
  bool changed = impl->ConvertLoadInt(function);
  changed |= impl->FoldPtrAdd(function);
  changed |= impl->FoldScaledIndex(function);
  return changed ? llvm::PreservedAnalyses::none()
                 : llvm::PreservedAnalyses::all();
}
}  // namespace anvill