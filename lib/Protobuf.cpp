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
#include <variant>

#include "anvill/Declarations.h"

namespace anvill {

Result<std::monostate, std::string> ProtobufTranslator::ParseIntoCallableDecl(
    const ::specification::Function &function, std::optional<uint64_t> address,
    CallableDecl &decl) const {
  decl.arch = arch;
  decl.is_noreturn = function.is_noreturn();
  decl.is_variadic = function.is_variadic();
  decl.calling_convention =
      static_cast<llvm::CallingConv::ID>(function.calling_convention());

  std::stringstream address_stream;

  if (address) {
    address_stream << std::hex << *address;
  } else {
    address_stream << "dummyfunc";
  }

  std::string address_str(address_stream.str());

  // NOTE (akshayk): An external function can have function type in the spec. If
  //                 the function type is available, it will have precedence over
  //                 the parameter variables and return values. If the function
  //                 type is not available it will fallback to processing params
  //                 and return values

  if (function.has_type()) {
    auto type_spec_result = DecodeType(function.type());
    if (!type_spec_result.Succeeded()) {
      std::string spec;
      function.SerializeToString(&spec);
      std::stringstream ss;
      ss << "Unable to parse manually-specified type for function at address "
         << address_str << " specification with type '" << spec
         << "': " << type_spec_result.TakeError();
      return {ss.str()};
    }

    auto type_spec = type_spec_result.TakeValue();
    auto type_result = type_translator.DecodeFromSpec(type_spec);
    if (!type_result.Succeeded()) {
      std::string spec;
      function.SerializeToString(&spec);
      std::stringstream ss;
      ss << "Unable to parse manually-specified type for function at address "
         << address_str << " specification with type '" << spec
         << "': " << type_result.TakeError().message;
      return {ss.str()};
    }

    auto func_type = llvm::dyn_cast<llvm::FunctionType>(
        remill::RecontextualizeType(type_result.TakeValue(), context));
    if (!func_type) {
      std::string spec;
      function.SerializeToString(&spec);
      std::stringstream ss;
      ss << "Type associated with function at address " << address_str
         << " and type specification '" << spec << "' is not a function type";
      return {ss.str()};
    }

    decl.spec_type = std::get<std::shared_ptr<FunctionType>>(type_spec);

    if (decl.is_variadic != func_type->isVarArg()) {
      std::string spec;
      function.SerializeToString(&spec);
      std::stringstream ss;
      ss << "Type associated with function at address " << address_str
         << " and type specification '" << spec
         << "' has a different variadic nature than the function "
         << "specification itself";
      return {ss.str()};
    }

    llvm::Module module("", context);
    arch->PrepareModule(&module);

    llvm::Function *dummy_function = llvm::Function::Create(
        func_type, llvm::Function::ExternalLinkage, "dummy", module);

    dummy_function->setCallingConv(decl.calling_convention);
    if (decl.is_noreturn) {
      dummy_function->addFnAttr(llvm::Attribute::NoReturn);
    }

    // Create a FunctionDecl object from the dummy function. This will set
    // the correct function types, bind the parameters & return values
    // with the architectural registers, and set the calling convention

    auto maybe_decl = FunctionDecl::Create(*dummy_function, arch);
    if (!maybe_decl.Succeeded()) {
      std::stringstream ss;
      ss << "Could not create function specification for function at address "
         << address_str << ": " << maybe_decl.TakeError();
      return {ss.str()};
    }

    decl = maybe_decl.TakeValue();

    // The function is not external and does not have associated type
    // in the spec. Fallback to processing parameters and return values
  } else {

    auto i = 0u;
    for (const ::specification::Parameter &param : function.parameters()) {
      auto maybe_param = DecodeParameter(param);
      if (maybe_param.Succeeded()) {
        decl.params.emplace_back(maybe_param.TakeValue());
      } else {
        auto err = maybe_param.TakeError();
        std::stringstream ss;
        ss << "Could not parse " << i << "th parameter of function at address "
           << address_str << ": " << err;
        return {ss.str()};
      }
      ++i;
    }

    // Get the return address location.
    if (function.has_return_address()) {
      auto ret_addr = function.return_address();
      auto maybe_ret =
          DecodeValue(ret_addr, "return address", true /* allow_void */);
      if (!maybe_ret.Succeeded()) {
        auto err = maybe_ret.TakeError();
        std::stringstream ss;
        ss << "Could not parse return address of function at address "
           << address_str << ": " << err;
        return {ss.str()};

      } else {
        decl.return_address = maybe_ret.TakeValue();

        // Looks like a void return type, i.e. function with no return address,
        // so make sure there's no location/value info.
        if (decl.return_address.type == void_type ||
            decl.return_address.type == dict_void_type) {
          if (decl.return_address.mem_offset || decl.return_address.mem_reg ||
              decl.return_address.reg) {
            std::stringstream ss;
            ss << "Return address of function at address " << address_str
               << " is marked as having a void type, but a location was "
               << "specified";
            return {ss.str()};
          }

          decl.return_address.type = void_type;

          // Make sure the return address is address-sized.
        } else {
          auto dl = arch->DataLayout();
          if (auto num_bits =
                  dl.getTypeAllocSizeInBits(decl.return_address.type);
              num_bits != arch->address_size) {
            std::stringstream ss;
            ss << "Return address of function at address " << address_str
               << std::dec << " is a " << num_bits
               << "-bit value, but address size for "
               << remill::GetArchName(arch->arch_name) << " is "
               << arch->address_size;
            return {ss.str()};
          }
        }
      }

      // A lack of a return address suggests that this function has no return
      // address, e.g. is something like `_start` on Linux, where there is no
      // logical place to return, and no return address is initialized in the
      // appropriate place in a register / on the stack by the kernel.
    } else {
      decl.return_address.type = void_type;
    }

    /*
    // Decode the value of the stack pointer on exit from the function, which is
    // defined in terms of `reg + offset` for a value of a register `reg`
    // on entry to the function.
    if (auto ret_sp = obj->getObject("return_stack_pointer")) {
      auto maybe_reg = ret_sp->getString("register");
      if (maybe_reg) {
        std::string reg_name = maybe_reg->str();
        decl.return_stack_pointer = arch->RegisterByName(reg_name);
        if (!decl.return_stack_pointer) {
          std::stringstream ss;
          ss << "Unable to locate register '" << reg_name
             << "' used computing the exit value of the "
             << "stack pointer in function at " << address_str;
          return JSONDecodeError(ss.str(), ret_sp);
        }
      } else {
        std::stringstream ss;
        ss << "Non-present or non-string 'register' in 'return_stack_pointer' "
           << "object of function specification at " << address_str;
        return JSONDecodeError(ss.str(), ret_sp);
      }

      auto maybe_offset = ret_sp->getInteger("offset");
      if (maybe_offset) {
        decl.return_stack_pointer_offset = *maybe_offset;
      }
    } else {
      std::stringstream ss;
      ss << "Non-present or non-object 'return_stack_pointer' in function "
         << "specification at " << address_str;
      return JSONDecodeError(ss.str(), obj);
    }
    */

    i = 0u;
    for (const ::specification::Value &ret : function.returns()) {
      auto maybe_ret = DecodeReturnValue(ret);
      if (maybe_ret.Succeeded()) {
        decl.returns.emplace_back(maybe_ret.TakeValue());
      } else {
        auto err = maybe_ret.TakeError();
        std::stringstream ss;
        ss << "Could not decode " << i << "th return value in function at "
           << address_str << ": " << err;
        return {ss.str()};
      }
      ++i;
    }

    // Figure out the return type of this function based off the return
    // values.
    llvm::Type *ret_type = nullptr;
    if (decl.returns.empty()) {
      ret_type = llvm::Type::getVoidTy(context);

    } else if (decl.returns.size() == 1) {
      ret_type = decl.returns[0].type;

      // The multiple return value case is most interesting, and somewhere
      // where we see some divergence between C and what we will decompile.
      // For example, on 32-bit x86, a 64-bit return value might be spread
      // across EAX:EDX. Instead of representing this by a single value, we
      // represent it as a structure if two 32-bit ints, and make sure to say
      // that one part is in EAX, and the other is in EDX.
    } else {
      llvm::SmallVector<llvm::Type *, 8> ret_types;
      for (auto &ret_val : decl.returns) {
        ret_types.push_back(ret_val.type);
      }
      ret_type = llvm::StructType::get(context, ret_types, false);
    }

    llvm::SmallVector<llvm::Type *, 8> param_types;
    for (auto &param_val : decl.params) {
      param_types.push_back(param_val.type);
    }

    decl.type =
        llvm::FunctionType::get(ret_type, param_types, decl.is_variadic);
  }

  return std::monostate();
}

ProtobufTranslator::ProtobufTranslator(
    const anvill::TypeTranslator &type_translator_, const remill::Arch *arch_)
    : arch(arch_),
      type_translator(type_translator_),
      context(*(arch->context)),
      void_type(llvm::Type::getVoidTy(context)),
      dict_void_type(remill::RecontextualizeType(
          type_translator.Dictionary().u.named.void_, context)) {}

// Decode the location of a value. This applies to both parameters and
// return values.
anvill::Result<ValueDecl, std::string>
ProtobufTranslator::DecodeValue(const ::specification::Value &value,
                                const char *desc, bool allow_void) const {
  ValueDecl decl;

  if (value.has_reg()) {
    auto &reg = value.reg();
    decl.reg = arch->RegisterByName(reg.register_name());
    if (!decl.reg) {
      std::stringstream ss;
      ss << "Unable to locate register '" << reg.register_name()
         << "' used for storing " << desc;
      return ss.str();
    }
  } else if (value.has_mem()) {
    auto &mem = value.mem();
    if (mem.has_base_reg()) {
      decl.mem_reg = arch->RegisterByName(mem.base_reg());
      if (!decl.mem_reg) {
        std::stringstream ss;
        ss << "Unable to locate base register '" << mem.base_reg()
           << "' used for storing " << desc;
        return ss.str();
      }
    }
    decl.mem_offset = mem.offset();
  } else {
    std::stringstream ss;
    ss << "A " << desc << " declaration must specify its location with "
       << "either a 'register' field or a 'memory' field";
    return ss.str();
  }

  if (!value.has_type()) {
    std::stringstream ss;
    ss << "A " << desc << " must specify a 'type'";
    return ss.str();
  }

  auto type = DecodeType(value.type());
  if (!type.Succeeded()) {
    std::stringstream ss;
    ss << "Couldn't parse the type for '" << desc << "': " << type.Error();
    return ss.str();
  }

  decl.spec_type = type.TakeValue();
  auto llvm_type = type_translator.DecodeFromSpec(decl.spec_type);
  if (!llvm_type.Succeeded()) {
    std::stringstream ss;
    ss << "Couldn't decode the type for '" << desc
       << "': " << llvm_type.Error().message;
    return ss.str();
  }
  decl.type = remill::RecontextualizeType(llvm_type.TakeValue(), context);

  return decl;
}

// Decode a parameter from the JSON spec. Parameters should have names,
// as that makes the bitcode slightly easier to read, but names are
// not required. They must have types, and these types should be mostly
// reflective of what you would see if you compiled C/C++ source code to
// LLVM bitcode, and inspected the type of the corresponding parameter in
// the bitcode.
Result<ParameterDecl, std::string> ProtobufTranslator::DecodeParameter(
    const ::specification::Parameter &param) const {
  auto maybe_decl = DecodeValue(param.value(), "function parameter");
  if (!maybe_decl.Succeeded()) {
    return maybe_decl.TakeError();
  }

  ParameterDecl decl;
  reinterpret_cast<ValueDecl &>(decl) = maybe_decl.TakeValue();

  if (param.has_name()) {
    decl.name = param.name();
  }

  return decl;
}

// Decode a return value from the JSON spec.
Result<ValueDecl, std::string>
ProtobufTranslator::DecodeReturnValue(const ::specification::Value &ret) const {
  return DecodeValue(ret, "function return value");
}

anvill::Result<TypeSpec, std::string>
ProtobufTranslator::DecodeType(const ::specification::TypeSpec &obj) const {
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
  if (obj.has_array()) {
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
  if (obj.has_struct_()) {
    auto res = std::make_shared<StructType>();
    for (auto elem : obj.struct_().members()) {
      auto maybe_type = DecodeType(elem);
      if (!maybe_type.Succeeded()) {
        return maybe_type.Error();
      }
      res->members.push_back(std::move(maybe_type.Value()));
    }
    return {std::move(res)};
  }
  if (obj.has_function()) {
    auto func = obj.function();
    if (!func.has_return_type()) {
      return {"Function without return type"};
    }
    auto res = std::make_shared<FunctionType>();
    auto maybe_ret = DecodeType(func.return_type());
    if (!maybe_ret.Succeeded()) {
      return maybe_ret.Error();
    }
    res->return_type = std::move(maybe_ret.Value());
    res->is_variadic = func.is_variadic();
    for (auto arg : func.arguments()) {
      auto maybe_argtype = DecodeType(arg);
      if (!maybe_argtype.Succeeded()) {
        return maybe_argtype.Error();
      }
      res->arguments.push_back(std::move(maybe_argtype.Value()));
    }
  }

  return {"Unknown/invalid data type"};
}

Result<CallableDecl, std::string> ProtobufTranslator::DecodeDefaultCallableDecl(
    const ::specification::Function &function) const {
  CallableDecl decl;

  auto parse_res = this->ParseIntoCallableDecl(function, std::nullopt, decl);
  if (!parse_res.Succeeded()) {
    return parse_res.TakeError();
  }

  return decl;
}

Result<FunctionDecl, std::string> ProtobufTranslator::DecodeFunction(
    const ::specification::Function &function) const {
  FunctionDecl decl;
  decl.address = function.entry_address();

  auto parse_res = this->ParseIntoCallableDecl(function, {decl.address}, decl);
  if (!parse_res.Succeeded()) {
    return parse_res.TakeError();
  }
  decl.context_assignments = {function.context_assignments().begin(),
                              function.context_assignments().end()};

  return decl;
}

Result<VariableDecl, std::string> ProtobufTranslator::DecodeGlobalVar(
    const ::specification::GlobalVariable &obj) const {
  anvill::VariableDecl decl;
  auto address = obj.address();
  decl.address = address;
  if (!obj.has_type()) {
    std::stringstream ss;
    ss << "Global variable at address " << std::hex << decl.address
       << " doesn't specify a type";
    return ss.str();
  }

  auto spec_type = DecodeType(obj.type());
  if (!spec_type.Succeeded()) {
    std::stringstream ss;
    ss << "Cannot decode type for variable at address " << std::hex
       << decl.address << ": " << spec_type.Error();
    return ss.str();
  }

  auto llvm_type = type_translator.DecodeFromSpec(spec_type.Value());
  if (!llvm_type.Succeeded()) {
    std::stringstream ss;
    ss << "Cannot translate type for variable at address " << std::hex
       << decl.address << ": " << llvm_type.Error().message;
    return ss.str();
  }

  auto type = llvm_type.TakeValue();
  if (type->isFunctionTy()) {
    std::stringstream ss;
    ss << "Global variable at address " << std::hex << address
       << " declared with function type should have been declared with a function specification";
    return ss.str();

  } else if (type == void_type || type == dict_void_type) {
    std::stringstream ss;
    ss << "Global variable at address " << std::hex << address
       << " cannot be declared with void type";
    return ss.str();

  } else if (!type->isSized()) {
    std::stringstream ss;
    ss << "Global variable at address " << std::hex << address
       << " cannot be declared with unsized type";
    return ss.str();
  }
  decl.type = type;

  return decl;
}

}  // namespace anvill
