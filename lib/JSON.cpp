/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/JSON.h>
#include <anvill/Type.h>
#include <glog/logging.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/Support/JSON.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <sstream>

namespace anvill {


Result<std::monostate, JSONDecodeError>
JSONTranslator::ParseJsonIntoCallableDecl(const llvm::json::Object *obj,
                                          std::optional<uint64_t> address,
                                          CallableDecl &decl) const {
  decl.arch = arch;


  if (auto maybe_is_noreturn = obj->getBoolean("is_noreturn")) {
    decl.is_noreturn = *maybe_is_noreturn;
  }

  if (auto maybe_is_variadic = obj->getBoolean("is_variadic")) {
    decl.is_variadic = *maybe_is_variadic;
  }

  if (auto maybe_cc = obj->getInteger("calling_convention")) {
    decl.calling_convention = static_cast<llvm::CallingConv::ID>(*maybe_cc);
  }


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

  auto maybe_type = obj->getString("type");
  if (maybe_type) {
    std::string spec = maybe_type->str();
    auto type_spec_result = type_translator.DecodeFromString(spec);
    if (!type_spec_result.Succeeded()) {
      std::stringstream ss;
      ss << "Unable to parse manually-specified type for function at address "
         << address_str << " specification with type '" << spec
         << "': " << type_spec_result.TakeError().message;
      return JSONDecodeError(ss.str(), obj);
    }

    auto func_type = llvm::dyn_cast<llvm::FunctionType>(
        remill::RecontextualizeType(type_spec_result.TakeValue(), context));
    if (!func_type) {
      std::stringstream ss;
      ss << "Type associated with function at address " << address_str
         << " and type specification '" << spec << "' is not a function type";
      return JSONDecodeError(ss.str(), obj);
    }

    if (decl.is_variadic != func_type->isVarArg()) {
      std::stringstream ss;
      ss << "Type associated with function at address " << address_str
         << " and type specification '" << spec
         << "' has a different variadic nature than the function "
         << "specification itself";
      return JSONDecodeError(ss.str(), obj);
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
      return JSONDecodeError(ss.str(), obj);
    }

    decl = maybe_decl.TakeValue();

    // The function is not external and does not have associated type
    // in the spec. Fallback to processing parameters and return values
  } else {

    if (auto params = obj->getArray("parameters")) {
      auto i = 0u;
      for (const llvm::json::Value &maybe_param : *params) {
        if (auto param_obj = maybe_param.getAsObject()) {
          auto maybe_param = DecodeParameter(param_obj);
          if (maybe_param.Succeeded()) {
            decl.params.emplace_back(maybe_param.TakeValue());
          } else {
            auto err = maybe_param.TakeError();
            std::stringstream ss;
            ss << "Could not parse " << i
               << "th parameter of function at address " << address_str << ": "
               << err.message;
            return JSONDecodeError(ss.str(), err.object);
          }
        } else {
          std::stringstream ss;
          ss << "Could not parse " << i
             << "th parameter of function at address " << address_str
             << ": not a JSON object";
          return JSONDecodeError(ss.str(), obj);
        }

        ++i;
      }
    }

    // Get the return address location.
    if (auto ret_addr = obj->getObject("return_address")) {
      auto maybe_ret =
          DecodeValue(ret_addr, "return address", true /* allow_void */);
      if (!maybe_ret.Succeeded()) {
        auto err = maybe_ret.TakeError();
        std::stringstream ss;
        ss << "Could not parse return address of function at address "
           << address_str << ": " << err.message;
        return JSONDecodeError(ss.str(), err.object);

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
            return JSONDecodeError(ss.str(), ret_addr);
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
            return JSONDecodeError(ss.str(), ret_addr);
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

    if (auto returns = obj->getArray("return_values")) {
      auto i = 0u;
      for (const llvm::json::Value &maybe_ret : *returns) {
        if (auto ret_obj = maybe_ret.getAsObject()) {
          auto maybe_ret = DecodeReturnValue(ret_obj);
          if (maybe_ret.Succeeded()) {
            decl.returns.emplace_back(maybe_ret.TakeValue());
          } else {
            auto err = maybe_ret.TakeError();
            std::stringstream ss;
            ss << "Could not decode " << i << "th return value in function at "
               << address_str << ": " << err.message;
            return JSONDecodeError(ss.str(), err.object);
          }
        } else {
          std::stringstream ss;
          ss << "Could not decode " << i << "th return value in function at "
             << address_str << ": non-object found in 'return_values' list";
          return JSONDecodeError(ss.str(), obj);
        }
        ++i;
      }
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


JSONTranslator::JSONTranslator(const TypeTranslator &type_translator_,
                               const remill::Arch *arch_)
    : arch(arch_),
      type_translator(type_translator_),
      context(*(arch->context)),
      void_type(llvm::Type::getVoidTy(context)),
      dict_void_type(remill::RecontextualizeType(
          type_translator.Dictionary().u.named.void_, context)) {}

// Decode the location of a value. This applies to both parameters and
// return values.
Result<ValueDecl, JSONDecodeError>
JSONTranslator::DecodeValue(const llvm::json::Object *obj, const char *desc,
                            bool allow_void) const {
  ValueDecl decl;

  auto has_reg = obj->find("register") != obj->end();
  auto has_mem = obj->find("memory") != obj->end();

  if (has_reg == has_mem && !allow_void) {
    std::stringstream ss;
    ss << "A " << desc << " declaration must specify its location with "
       << "either a 'register' field or a 'memory' field";
    return JSONDecodeError(ss.str(), obj);
  }

  auto maybe_reg = obj->getString("register");
  if (maybe_reg) {
    decl.reg = arch->RegisterByName(maybe_reg->str());
    if (!decl.reg) {
      std::stringstream ss;
      ss << "Unable to locate register '" << maybe_reg->str()
         << "' used for storing " << desc;
      return JSONDecodeError(ss.str(), obj);
    }
  } else if (has_reg) {
    std::stringstream ss;
    ss << "The 'register' field of a " << desc << " must be a string";
    return JSONDecodeError(ss.str(), obj);
  }

  if (auto mem_obj = obj->getObject("memory")) {
    maybe_reg = mem_obj->getString("register");
    if (maybe_reg) {
      auto reg_name = maybe_reg->str();
      if (reg_name == "MEMORY") {
        // Absolute offset.
      } else {
        decl.mem_reg = arch->RegisterByName(reg_name);
        if (!decl.mem_reg) {
          std::stringstream ss;
          ss << "Unable to locate memory base register '" << maybe_reg->str()
             << "' used for storing " << desc;
          return JSONDecodeError(ss.str(), mem_obj);
        }
      }
    }

    auto maybe_offset = mem_obj->getInteger("offset");
    if (maybe_offset) {
      decl.mem_offset = *maybe_offset;
    }
  } else if (has_mem) {
    std::stringstream ss;
    ss << "The 'memory' field of a " << desc << " must be an object";
    return JSONDecodeError(ss.str(), obj);
  }

  if (auto maybe_type_str = obj->getString("type")) {
    std::string spec = maybe_type_str->str();
    auto type_spec_res = type_translator.DecodeFromString(spec);
    if (!type_spec_res.Succeeded()) {
      std::stringstream ss;
      ss << "Unable to parse " << desc << " specification '" << spec
         << "': " << type_spec_res.TakeError().message;
      return JSONDecodeError(ss.str(), obj);
    }

    decl.type = remill::RecontextualizeType(type_spec_res.TakeValue(), context);
    if (decl.type == void_type || decl.type == dict_void_type) {
      if (!allow_void) {
        std::stringstream ss;
        ss << "Type specification '" << spec << "' of " << desc
           << " is not allowed to be the void type";
        return JSONDecodeError(ss.str(), obj);
      } else {
        decl.type = void_type;
      }
    } else if (!decl.type->isSized()) {
      std::stringstream ss;
      ss << "Type specification '" << spec << "' of " << desc
         << " is not sized";
      return JSONDecodeError(ss.str(), obj);
    }

  } else if (obj->find("type") != obj->end()) {
    std::stringstream ss;
    ss << "A " << desc << " must specify a 'type' as a string";
    return JSONDecodeError(ss.str(), obj);
  }

  if (!allow_void) {
    if (decl.reg && decl.mem_reg) {
      std::stringstream ss;
      ss << "A " << desc << " cannot be resident in both a register "
         << "and a memory location";
      return JSONDecodeError(ss.str(), obj);

    } else if (!decl.reg && !(decl.mem_reg || decl.mem_offset)) {
      std::stringstream ss;
      ss << "A " << desc << " must be resident in either a register or "
         << "a memory location (defined in terms of a register and offset)";
      return JSONDecodeError(ss.str(), obj);
    }
  }

  return decl;
}

// Decode a parameter from the JSON spec. Parameters should have names,
// as that makes the bitcode slightly easier to read, but names are
// not required. They must have types, and these types should be mostly
// reflective of what you would see if you compiled C/C++ source code to
// LLVM bitcode, and inspected the type of the corresponding parameter in
// the bitcode.
Result<ParameterDecl, JSONDecodeError>
JSONTranslator::DecodeParameter(const llvm::json::Object *obj) const {
  auto maybe_decl = DecodeValue(obj, "function parameter");
  if (!maybe_decl.Succeeded()) {
    return maybe_decl.TakeError();
  }

  ParameterDecl decl;
  reinterpret_cast<ValueDecl &>(decl) = maybe_decl.TakeValue();

  if (auto maybe_name = obj->getString("name"); maybe_name) {
    decl.name = maybe_name->str();
  }

  return decl;
}

// Decode a return value from the JSON spec.
Result<ValueDecl, JSONDecodeError>
JSONTranslator::DecodeReturnValue(const llvm::json::Object *obj) const {
  return DecodeValue(obj, "function return value");
}


Result<CallableDecl, JSONDecodeError>
JSONTranslator::DecodeDefaultCallableDecl(const llvm::json::Object *obj) const {
  CallableDecl decl;

  auto parse_res = this->ParseJsonIntoCallableDecl(obj, std::nullopt, decl);
  if (!parse_res.Succeeded()) {
    return parse_res.TakeError();
  }

  return decl;
}

// Try to unserialize function info from a JSON specification. These
// are really function prototypes / declarations, and not any isntruction
// data (that is separate, if present).
Result<FunctionDecl, JSONDecodeError>
JSONTranslator::DecodeFunction(const llvm::json::Object *obj) const {

  FunctionDecl decl;

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    return JSONDecodeError("Missing function address in specification", obj);
  }

  const auto address = static_cast<uint64_t>(*maybe_ea);
  decl.address = address;


  auto parse_res = this->ParseJsonIntoCallableDecl(obj, {address}, decl);
  if (!parse_res.Succeeded()) {
    return parse_res.TakeError();
  }
  return decl;
}

// Try to decode call site information from a JSON specification. This is a
// lot like function declarations, but is specific to a call site, rather
// than specific to the function's entrypoint.
Result<CallSiteDecl, JSONDecodeError>
JSONTranslator::DecodeCallSite(const llvm::json::Object *obj) const {

  CallSiteDecl decl;

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    return JSONDecodeError(
        "Missing call site address in call site specification", obj);
  }

  auto maybe_func_ea = obj->getInteger("function_address");
  if (!maybe_func_ea) {
    return JSONDecodeError(
        "Missing containing function address in call site specification", obj);
  }

  const auto address = static_cast<uint64_t>(*maybe_ea);

  decl.arch = arch;
  decl.address = address;
  decl.function_address = static_cast<uint64_t>(*maybe_func_ea);

  if (auto maybe_is_noreturn = obj->getBoolean("is_noreturn")) {
    decl.is_noreturn = *maybe_is_noreturn;
  }

  if (auto maybe_is_variadic = obj->getBoolean("is_variadic")) {
    decl.is_variadic = *maybe_is_variadic;
  }

  if (auto maybe_cc = obj->getInteger("calling_convention")) {
    decl.calling_convention = static_cast<llvm::CallingConv::ID>(*maybe_cc);
  }

  if (auto params = obj->getArray("parameters")) {
    auto i = 0u;
    for (const llvm::json::Value &maybe_param : *params) {
      if (auto param_obj = maybe_param.getAsObject()) {
        auto maybe_param = DecodeParameter(param_obj);
        if (maybe_param.Succeeded()) {
          decl.params.emplace_back(maybe_param.TakeValue());
        } else {
          auto err = maybe_param.TakeError();
          std::stringstream ss;
          ss << "Could not parse " << i
             << "th parameter of call site at address " << std::hex << address
             << ": " << err.message;
          return JSONDecodeError(ss.str(), err.object);
        }
      } else {
        std::stringstream ss;
        ss << "Could not parse " << i << "th parameter of call site at address "
           << std::hex << address << ": not a JSON object";
        return JSONDecodeError(ss.str(), obj);
      }

      ++i;
    }
  }

  // Get the return address location.
  if (auto ret_addr = obj->getObject("return_address")) {
    auto maybe_ret =
        DecodeValue(ret_addr, "return address", true /* allow_void */);
    if (!maybe_ret.Succeeded()) {
      auto err = maybe_ret.TakeError();
      std::stringstream ss;
      ss << "Could not parse return address of call site at address "
         << std::hex << address << ": " << err.message;
      return JSONDecodeError(ss.str(), err.object);

    } else {
      decl.return_address = maybe_ret.TakeValue();

      // Looks like a void return type, i.e. function with no return address,
      // so make sure there's no location/value info.
      if (decl.return_address.type == void_type ||
          decl.return_address.type == dict_void_type) {
        if (decl.return_address.mem_offset || decl.return_address.mem_reg ||
            decl.return_address.reg) {
          std::stringstream ss;
          ss << "Return address of call site at address " << std::hex << address
             << " is marked as having a void type, but a location was "
             << "specified";
          return JSONDecodeError(ss.str(), ret_addr);
        }

        decl.return_address.type = void_type;

        // Make sure the return address is address-sized.
      } else {
        auto dl = arch->DataLayout();
        if (auto num_bits = dl.getTypeAllocSizeInBits(decl.return_address.type);
            num_bits != arch->address_size) {
          std::stringstream ss;
          ss << "Return address of call site at address " << std::hex << address
             << std::dec << " is a " << num_bits
             << "-bit value, but address size for "
             << remill::GetArchName(arch->arch_name) << " is "
             << arch->address_size;
          return JSONDecodeError(ss.str(), ret_addr);
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
           << "stack pointer in call site at " << std::hex << address;
        return JSONDecodeError(ss.str(), ret_sp);
      }
    } else {
      std::stringstream ss;
      ss << "Non-present or non-string 'register' in 'return_stack_pointer' "
         << "object of call site specification at " << std::hex << decl.address;
      return JSONDecodeError(ss.str(), ret_sp);
    }

    auto maybe_offset = ret_sp->getInteger("offset");
    if (maybe_offset) {
      decl.return_stack_pointer_offset = *maybe_offset;
    }
  } else {
    std::stringstream ss;
    ss << "Non-present or non-object 'return_stack_pointer' in call site "
       << "specification at " << std::hex << address;
    return JSONDecodeError(ss.str(), obj);
  }

  if (auto returns = obj->getArray("return_values")) {
    auto i = 0u;
    for (const llvm::json::Value &maybe_ret : *returns) {
      if (auto ret_obj = maybe_ret.getAsObject()) {
        auto maybe_ret = DecodeReturnValue(ret_obj);
        if (maybe_ret.Succeeded()) {
          decl.returns.emplace_back(maybe_ret.TakeValue());
        } else {
          auto err = maybe_ret.TakeError();
          std::stringstream ss;
          ss << "Could not decode " << i << "th return value in call site at "
             << std::hex << address << ": " << err.message;
          return JSONDecodeError(ss.str(), err.object);
        }
      } else {
        std::stringstream ss;
        ss << "Could not decode " << i << "th return value in call site at "
           << std::hex << address
           << ": non-object found in 'return_values' list";
        return JSONDecodeError(ss.str(), obj);
      }
      ++i;
    }
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

  decl.type = llvm::FunctionType::get(ret_type, param_types, decl.is_variadic);

  return decl;
}

// Try to decode global variable information from a JSON specification. These
// are really variable prototypes / declarations.
Result<VariableDecl, JSONDecodeError>
JSONTranslator::DecodeGlobalVar(const llvm::json::Object *obj) const {
  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    return JSONDecodeError(
        "Missing 'address' field in global variable specification", obj);
  }

  auto address = static_cast<uint64_t>(*maybe_ea);

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    std::stringstream ss;
    ss << "Missing 'type' field in specification of global variable at address "
       << std::hex << address;
    return JSONDecodeError(ss.str(), obj);
  }

  std::string spec = maybe_type_str->str();
  auto type_spec_res = type_translator.DecodeFromString(spec);
  if (!type_spec_res.Succeeded()) {
    auto error = type_spec_res.TakeError();
    std::stringstream ss;
    ss << "Unable to decode type '" << spec
       << "' of global variable at address " << std::hex << address << ": "
       << error.message;
    return JSONDecodeError(ss.str(), obj);
  }

  llvm::Type *type = type_spec_res.TakeValue();

  if (type->isFunctionTy()) {
    std::stringstream ss;
    ss << "Global variable at address " << std::hex << address
       << " declared with function type '" << spec
       << "' should have been declared with a function specification";
    return JSONDecodeError(ss.str(), obj);

  } else if (type == void_type || type == dict_void_type) {
    std::stringstream ss;
    ss << "Global variable at address " << std::hex << address
       << " cannot be declared with void type";
    return JSONDecodeError(ss.str(), obj);

  } else if (!type->isSized()) {
    std::stringstream ss;
    ss << "Global variable at address " << std::hex << address
       << " cannot be declared with unsized type '" << spec << "'";
    return JSONDecodeError(ss.str(), obj);
  }

  anvill::VariableDecl decl;
  decl.type = type;
  decl.address = address;
  return decl;
}

namespace {

// Serialize a ValueDecl to JSON
static Result<llvm::json::Object, JSONEncodeError>
SerializeValueToJSON(const ValueDecl &decl, const TypeTranslator &translator) {
  llvm::json::Object value_json;

  if (decl.reg) {

    // The value is in a register
    value_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("register"),
                                             decl.reg->name});
  } else if (decl.mem_reg || decl.mem_offset) {

    // The value is in memory
    llvm::json::Object memory_json;
    if (decl.mem_reg) {
      memory_json.insert(llvm::json::Object::KV{
          llvm::json::ObjectKey("register"), decl.mem_reg->name});
    }

    if (decl.mem_offset) {
      memory_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("offset"),
                                                decl.mem_offset});
    }

    // Wrap the memory_json structure in a memory block
    value_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("memory"),
                               llvm::json::Value(std::move(memory_json))});

  } else {
    return JSONEncodeError("Trying to serialize a value that has no location",
                           &decl);
  }

  if (decl.type) {
    value_json.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("type"), translator.EncodeToString(decl.type)});
  } else {
    return JSONEncodeError("Trying to serialize a value that has no type",
                           &decl);
  }

  return value_json;
}

// Serialize a ParameterDecl to JSON
static Result<llvm::json::Object, JSONEncodeError>
SerializeParamToJSON(const ParameterDecl &decl,
                     const TypeTranslator &translator) {
  auto maybe_val = SerializeValueToJSON(decl, translator);
  if (maybe_val.Succeeded()) {
    auto param_json = maybe_val.TakeValue();
    param_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("name"), decl.name});
    return param_json;
  } else {
    return maybe_val.TakeError();
  }
}

}  // namespace

// Encode a function declaration.
Result<llvm::json::Object, JSONEncodeError>
JSONTranslator::Encode(const FunctionDecl &decl) const {

  if (!decl.arch) {
    return JSONEncodeError(
        "Cannot encode function declaration with no architecture");
  }

  if (!decl.type) {
    return JSONEncodeError(
        "Cannot encode function declaration with no function type");
  }

  if (!decl.return_stack_pointer) {
    return JSONEncodeError(
        "Cannot encode function declaration with no return stack pointer");
  }

  if (!decl.return_address.type) {
    return JSONEncodeError(
        "Cannot encode function declaration with no return address type");
  }

  if (decl.arch != arch) {
    if (decl.arch->arch_name != arch->arch_name ||
        decl.arch->os_name != arch->os_name) {
      return JSONEncodeError(
          "Cannot encode function declaration with different architecture/OS");
    }
  }

  llvm::json::Object json;

  if (decl.address) {
    json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("address"),
                                       static_cast<int64_t>(decl.address)});
  }

  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("is_variadic"),
                                     decl.is_variadic});

  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("is_noreturn"),
                                     decl.is_noreturn});

  llvm::json::Array params_json;
  for (const auto &pdecl : decl.params) {
    auto maybe_val = SerializeParamToJSON(pdecl, type_translator);
    if (maybe_val.Succeeded()) {
      params_json.emplace_back(maybe_val.TakeValue());
    } else {
      return maybe_val.TakeError();
    }
  }

  llvm::json::Array returns_json;
  for (const auto &rdecl : decl.returns) {
    auto maybe_val = SerializeValueToJSON(rdecl, type_translator);
    if (maybe_val.Succeeded()) {
      returns_json.emplace_back(maybe_val.TakeValue());
    } else {
      return maybe_val.TakeError();
    }
  }

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("parameters"),
                             llvm::json::Value(std::move(params_json))});

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("return_values"),
                             llvm::json::Value(std::move(returns_json))});

  llvm::json::Object return_stack_pointer_json;
  return_stack_pointer_json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("register"), decl.return_stack_pointer->name});
  return_stack_pointer_json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("offset"), decl.return_stack_pointer_offset});
  return_stack_pointer_json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("type"),
      type_translator.EncodeToString(decl.return_stack_pointer->type)});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("return_stack_pointer"),
      llvm::json::Value(std::move(return_stack_pointer_json))});

  if (decl.return_address.type != void_type &&
      decl.return_address.type != dict_void_type) {
    auto maybe_val = SerializeValueToJSON(decl.return_address, type_translator);
    if (maybe_val.Succeeded()) {
      json.insert(
          llvm::json::Object::KV{llvm::json::ObjectKey("return_address"),
                                 llvm::json::Value(maybe_val.TakeValue())});
    } else {
      return maybe_val.TakeError();
    }
  }

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("calling_convention"),
                             llvm::json::Value(decl.calling_convention)});

  return json;
}

// Encode a call site declaration.
Result<llvm::json::Object, JSONEncodeError>
JSONTranslator::Encode(const CallSiteDecl &decl) const {

  if (!decl.address) {
    return JSONEncodeError(
        "Cannot encode call site declaration with no address");
  }

  if (!decl.function_address) {
    return JSONEncodeError(
        "Cannot encode call site declaration with no containing function address");
  }

  if (!decl.arch) {
    return JSONEncodeError(
        "Cannot encode call site declaration with no architecture");
  }

  if (!decl.type) {
    return JSONEncodeError(
        "Cannot encode call site declaration with no function type");
  }

  if (!decl.return_stack_pointer) {
    return JSONEncodeError(
        "Cannot encode call site declaration with no return stack pointer");
  }

  if (!decl.return_address.type) {
    return JSONEncodeError(
        "Cannot encode call site declaration with no return address type");
  }

  if (decl.arch != arch) {
    if (decl.arch->arch_name != arch->arch_name ||
        decl.arch->os_name != arch->os_name) {
      return JSONEncodeError(
          "Cannot encode call site declaration with different architecture/OS");
    }
  }

  llvm::json::Object json;

  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("address"),
                                     static_cast<int64_t>(decl.address)});

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("function_address"),
                             static_cast<int64_t>(decl.function_address)});

  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("is_variadic"),
                                     decl.is_variadic});

  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("is_noreturn"),
                                     decl.is_noreturn});

  llvm::json::Array params_json;
  for (const auto &pdecl : decl.params) {
    auto maybe_val = SerializeParamToJSON(pdecl, type_translator);
    if (maybe_val.Succeeded()) {
      params_json.emplace_back(maybe_val.TakeValue());
    } else {
      return maybe_val.TakeError();
    }
  }

  llvm::json::Array returns_json;
  for (const auto &rdecl : decl.returns) {
    auto maybe_val = SerializeValueToJSON(rdecl, type_translator);
    if (maybe_val.Succeeded()) {
      returns_json.emplace_back(maybe_val.TakeValue());
    } else {
      return maybe_val.TakeError();
    }
  }

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("parameters"),
                             llvm::json::Value(std::move(params_json))});

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("return_values"),
                             llvm::json::Value(std::move(returns_json))});

  llvm::json::Object return_stack_pointer_json;
  return_stack_pointer_json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("register"), decl.return_stack_pointer->name});
  return_stack_pointer_json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("offset"), decl.return_stack_pointer_offset});
  return_stack_pointer_json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("type"),
      type_translator.EncodeToString(decl.return_stack_pointer->type)});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("return_stack_pointer"),
      llvm::json::Value(std::move(return_stack_pointer_json))});

  if (decl.return_address.type != void_type &&
      decl.return_address.type != dict_void_type) {
    auto maybe_val = SerializeValueToJSON(decl.return_address, type_translator);
    if (maybe_val.Succeeded()) {
      json.insert(
          llvm::json::Object::KV{llvm::json::ObjectKey("return_address"),
                                 llvm::json::Value(maybe_val.TakeValue())});
    } else {
      return maybe_val.TakeError();
    }
  }

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("calling_convention"),
                             llvm::json::Value(decl.calling_convention)});

  return json;
}

// Encode a variable declaration.
Result<llvm::json::Object, JSONEncodeError>
JSONTranslator::Encode(const VariableDecl &decl) const {
  if (!decl.type) {
    return JSONEncodeError("Cannot encode variable declaration with no type");
  }

  llvm::json::Object json;

  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("address"),
                                     static_cast<int64_t>(decl.address)});

  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("type"),
                             type_translator.EncodeToString(decl.type)});

  return json;
}

}  // namespace anvill
