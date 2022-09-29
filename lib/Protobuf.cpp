/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "Protobuf.h"

#include <anvill/Type.h>
#include <glog/logging.h>
#include <llvm/IR/DataLayout.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <memory>
#include <sstream>

namespace anvill {

ProtobufTranslator::ProtobufTranslator(
    const anvill::TypeTranslator &type_translator_, const remill::Arch *arch_)
    : arch(arch_),
      type_translator(type_translator_),
      context(*(arch->context)),
      void_type(llvm::Type::getVoidTy(context)),
      dict_void_type(remill::RecontextualizeType(
          type_translator.Dictionary().u.named.void_, context)) {}

anvill::Result<TypeSpec, std::string>
ProtobufTranslator::DecodeType(const ::specification::TypeSpec &obj) {
  if (obj.has_base()) {
    auto base = obj.base();
    return {static_cast<BaseType>(base)};
  }
  if (obj.has_unknown()) {
    return {UnknownType{obj.unknown()}};
  }
  if (obj.has_pointer()) {
    auto pointer = obj.pointer();
    TypeSpec pointee = BaseType::Void;
    if (pointer.has_pointee()) {
      auto maybe_pointee = DecodeType(pointer.pointee());
      if (!maybe_pointee.Succeeded()) {
        return maybe_pointee.Error();
      }
      pointee = maybe_pointee.Value();
    }
    return {std::make_shared<PointerType>(pointee, pointer.const_())};
  }
  if (obj.has_vector()) {
    auto vector = obj.vector();
    if (!vector.has_base()) {
      return {"Vector type without base type"};
    }
    auto maybe_base = DecodeType(vector.base());
    if (!maybe_base.Succeeded()) {
      return maybe_base.Error();
    }
    return {std::make_shared<VectorType>(maybe_base.Value(), vector.size())};
  }
  if(obj.has_array()) {
    auto array = obj.array();
    if (!array.has_base()) {
      return {"Array type without base type"};
    }
    auto maybe_base = DecodeType(array.base());
    if (!maybe_base.Succeeded()) {
      return maybe_base.Error();
    }
    return {std::make_shared<ArrayType>(maybe_base.Value(), array.size())};
  }
  if(obj.has_struct_()) {
    auto res = std::make_shared<StructType>();
    for(auto elem : obj.struct_().members()) {
        auto maybe_type = DecodeType(elem);
        if(!maybe_type.Succeeded()) {
            return maybe_type.Error();
        }
        res->members.push_back(std::move(maybe_type.Value()));
    }
    return {std::move(res)};
  }
  if(obj.has_function()) {
    auto func = obj.function();
    if(!func.has_return_type()) {
        return {"Function without return type"};
    }
    auto res = std::make_shared<FunctionType>();
    auto maybe_ret = DecodeType(func.return_type());
    if(!maybe_ret.Succeeded()) {
        return maybe_ret.Error();
    }
    res->return_type = std::move(maybe_ret.Value());
    res->is_variadic = func.is_variadic();
    for(auto arg : func.arguments()) {
        auto maybe_argtype = DecodeType(arg);
        if(!maybe_argtype.Succeeded()) {
            return maybe_argtype.Error();
        }
        res->arguments.push_back(std::move(maybe_argtype.Value()));
    }
  }

  return {"Unknown/invalid data type"};
}

Result<FunctionDecl, std::string>
ProtobufTranslator::DecodeFunction(const ::specification::Function &) const {
  return {"Not implemented!"};
}

Result<VariableDecl, std::string> ProtobufTranslator::DecodeGlobalVar(
    const ::specification::GlobalVariable &) const {
  return {"Not implemented!"};
}

}  // namespace anvill
