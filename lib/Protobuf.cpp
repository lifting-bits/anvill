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
#include <llvm/IR/DerivedTypes.h>
#include <llvm/Support/Casting.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "anvill/Declarations.h"
#include "specification.pb.h"

namespace anvill {

static BaseType SizeToType(unsigned size) {
  std::unordered_map<unsigned, BaseType> types = {
      {8, BaseType::UInt8},   {16, BaseType::UInt16}, {24, BaseType::UInt24},
      {32, BaseType::UInt32}, {64, BaseType::UInt64}, {128, BaseType::UInt128}};
  return types[size];
}

Result<std::monostate, std::string> ProtobufTranslator::ParseIntoCallableDecl(
    const ::specification::Callable &function, std::optional<uint64_t> address,
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

    auto type_spec = type_spec_result.Value();
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
        remill::RecontextualizeType(type_result.Value(), context));
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

    decl = maybe_decl.Value();

    // The function is not external and does not have associated type
    // in the spec. Fallback to processing parameters and return values
  } else {

    auto i = 0u;
    for (const ::specification::Parameter &param : function.parameters()) {
      auto maybe_param = DecodeParameter(param);
      if (maybe_param.Succeeded()) {
        decl.params.emplace_back(maybe_param.Value());
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
      auto maybe_low_loc_ret_addr = DecodeLowLoc(ret_addr, "return address");
      if (!maybe_low_loc_ret_addr.Succeeded()) {
        return maybe_low_loc_ret_addr.TakeError();
      }

      std::vector<LowLoc> low_loc_ret_addr = {
          maybe_low_loc_ret_addr.TakeValue()};
      auto maybe_ret = ValueDeclFromOrderedLowLoc(
          low_loc_ret_addr, SizeToType(arch->address_size), "return address");
      if (!maybe_ret.Succeeded()) {
        auto err = maybe_ret.TakeError();
        std::stringstream ss;
        ss << "Could not parse return address of function at address "
           << address_str << ": " << err;
        return {ss.str()};
      }
      decl.return_address = maybe_ret.Value();

      // A lack of a return address suggests that this function has no return
      // address, e.g. is something like `_start` on Linux, where there is no
      // logical place to return, and no return address is initialized in the
      // appropriate place in a register / on the stack by the kernel.
    } else {
      DLOG(INFO) << "Function at: " << address_str << " has no return";
      decl.return_address.type = void_type;
    }

    // Decode the value of the stack pointer on exit from the function, which is
    // defined in terms of `reg + offset` for a value of a register `reg`
    // on entry to the function.
    if (function.has_return_stack_pointer()) {
      auto ret_sp = function.return_stack_pointer();
      if (ret_sp.has_reg()) {
        std::string reg_name = ret_sp.reg().register_name();
        decl.return_stack_pointer = arch->RegisterByName(reg_name);
        if (!decl.return_stack_pointer) {
          std::stringstream ss;
          ss << "Unable to locate register '" << reg_name
             << "' used computing the exit value of the "
             << "stack pointer in function at " << address_str;
          return {ss.str()};
        }
      } else {
        std::stringstream ss;
        ss << "Non-present or non-string 'register' in 'return_stack_pointer' "
           << "object of function specification at " << address_str;
        return {ss.str()};
      }

      if (ret_sp.has_offset()) {
        decl.return_stack_pointer_offset = ret_sp.offset();
      }
    } else {
      std::stringstream ss;
      ss << "Non-present or non-object 'return_stack_pointer' in function "
         << "specification at " << address_str;
      return {ss.str()};
    }

    auto maybe_ret_type = DecodeType(function.return_().type());
    if (!maybe_ret_type.Succeeded()) {
      return maybe_ret_type.TakeError();
    }

    i = 0u;


    auto maybe_ret =
        DecodeValueDecl(function.return_().values(), maybe_ret_type.TakeValue(),
                        "return value");
    if (!maybe_ret.Succeeded()) {
      auto err = maybe_ret.TakeError();
      std::stringstream ss;
      ss << "Could not decode " << i << "th return value in function at "
         << address_str << ": " << err;
      return {ss.str()};
    }
    decl.returns = maybe_ret.TakeValue();


    // Figure out the return type of this function based off the return
    // values.
    llvm::Type *ret_type = ret_type = decl.returns.type;
    if (decl.returns.ordered_locs.empty()) {
      ret_type = llvm::Type::getVoidTy(context);
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
    const anvill::TypeTranslator &type_translator_, const remill::Arch *arch_,
    std::unordered_map<std::int64_t, TypeSpec> &type_map,
    std::unordered_map<std::int64_t, std::string> &type_names)
    : arch(arch_),
      type_translator(type_translator_),
      context(*(arch->context)),
      void_type(llvm::Type::getVoidTy(context)),
      dict_void_type(remill::RecontextualizeType(
          type_translator.Dictionary().u.named.void_, context)),
      type_map(type_map),
      type_names(type_names) {}


anvill::Result<LowLoc, std::string>
ProtobufTranslator::DecodeLowLoc(const ::specification::Value &value,
                                 const char *desc) const {
  LowLoc loc;
  if (value.has_reg()) {
    auto &reg = value.reg();
    loc.reg = arch->RegisterByName(reg.register_name());
    if (!loc.reg) {
      std::stringstream ss;
      ss << "Unable to locate register '" << reg.register_name()
         << "' used for storing " << desc;
      return ss.str();
    }
    if (reg.has_subreg_sz()) {
      loc.size = reg.subreg_sz();
    }

  } else if (value.has_mem()) {
    auto &mem = value.mem();
    if (mem.has_base_reg()) {
      loc.mem_reg = arch->RegisterByName(mem.base_reg());
      if (!loc.mem_reg) {
        std::stringstream ss;
        ss << "Unable to locate base register '" << mem.base_reg()
           << "' used for storing " << desc;
        return ss.str();
      }
    }
    loc.mem_offset = mem.offset();
    loc.size = mem.size();
  } else {
    std::stringstream ss;
    ss << "A " << desc << " declaration must specify its location with "
       << "either a 'register' field or a 'memory' field";
    return ss.str();
  }

  return loc;
}

anvill::Result<ValueDecl, std::string>
ProtobufTranslator::ValueDeclFromOrderedLowLoc(std::vector<LowLoc> loc,
                                               TypeSpec type,
                                               const char *desc) const {

  ValueDecl decl;
  decl.ordered_locs = std::move(loc);
  decl.spec_type = type;
  auto llvm_type = type_translator.DecodeFromSpec(decl.spec_type);
  if (!llvm_type.Succeeded()) {
    std::stringstream ss;
    ss << "Couldn't decode the type for '" << desc
       << "': " << llvm_type.Error().message;
    return ss.str();
  }
  decl.type = remill::RecontextualizeType(llvm_type.Value(), context);

  return decl;
}


// Decode the location of a value. This applies to both parameters and
// return values.
anvill::Result<ValueDecl, std::string> ProtobufTranslator::DecodeValueDecl(
    const ::google::protobuf::RepeatedPtrField<::specification::Value> &values,
    TypeSpec type, const char *desc) const {
  std::vector<LowLoc> locs;
  for (const auto &val : values) {
    auto loc = DecodeLowLoc(val, desc);
    if (!loc.Succeeded()) {
      return loc.TakeError();
    }
    locs.push_back(loc.TakeValue());
  }

  return ValueDeclFromOrderedLowLoc(std::move(locs), type, desc);
}


// Decode a parameter from the JSON spec. Parameters should have names,
// as that makes the bitcode slightly easier to read, but names are
// not required. They must have types, and these types should be mostly
// reflective of what you would see if you compiled C/C++ source code to
// LLVM bitcode, and inspected the type of the corresponding parameter in
// the bitcode.
Result<ParameterDecl, std::string> ProtobufTranslator::DecodeParameter(
    const ::specification::Parameter &param) const {
  if (!param.has_repr_var()) {
    return {"Parameter with no representation"};
  }
  auto &repr_var = param.repr_var();

  if (!repr_var.has_type()) {
    return {"Parameter without type spec"};
  }
  auto maybe_type = DecodeType(repr_var.type());
  if (!maybe_type.Succeeded()) {
    return maybe_type.TakeError();
  }

  auto maybe_decl = DecodeValueDecl(repr_var.values(), maybe_type.Value(),
                                    "function parameter");
  if (!maybe_decl.Succeeded()) {
    return maybe_decl.TakeError();
  }

  ParameterDecl decl;
  reinterpret_cast<ValueDecl &>(decl) = maybe_decl.Value();

  if (param.has_name()) {
    decl.name = param.name();
  }

  return decl;
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
  if (obj.has_alias()) {
    if (this->type_names.count(obj.alias())) {
      TypeSpec res = TypeName(type_names.at(obj.alias()));
      return res;
    } else if (this->type_map.count(obj.alias())) {
      TypeSpec tspec = this->type_map.at(obj.alias());
      return tspec;
    } else {
      LOG(ERROR) << "Unknown alias id " << obj.alias();
      return {BaseType::Void};
    }
  }

  return {"Unknown/invalid data type" + obj.DebugString()};
}

Result<CallableDecl, std::string> ProtobufTranslator::DecodeDefaultCallableDecl(
    const ::specification::Function &function) const {
  CallableDecl decl;


  if (!function.has_callable()) {
    return std::string("all functions should have a callable");
  }

  auto parse_res =
      this->ParseIntoCallableDecl(function.callable(), std::nullopt, decl);
  if (!parse_res.Succeeded()) {
    return parse_res.TakeError();
  }

  return decl;
}


Result<CallSiteDecl, std::string>
ProtobufTranslator::DecodeCallsite(const ::specification::Callsite &cs) const {
  CallSiteDecl cs_decl;

  if (!cs.has_callable()) {
    return std::string("all callsites should have a callable");
  }

  auto parse_res =
      this->ParseIntoCallableDecl(cs.callable(), std::nullopt, cs_decl);
  if (!parse_res.Succeeded()) {
    return parse_res.TakeError();
  }

  cs_decl.address = cs.call_address();
  cs_decl.function_address = cs.inside_function_address();

  return cs_decl;
}

Result<FunctionDecl, std::string> ProtobufTranslator::DecodeFunction(
    const ::specification::Function &function) const {
  FunctionDecl decl;
  decl.address = function.entry_address();
  decl.entry_uid = Uid{function.entry_uid()};


  if (function.binary_addr().has_ext_address()) {
    auto ext = function.binary_addr().ext_address();
    decl.binary_addr = RelAddr{ext.entry_vaddr(), ext.displacement()};
  } else {
    decl.binary_addr = function.binary_addr().internal_address();
  }

  if (!function.has_callable()) {
    return std::string("all functions should have a callable");
  }

  auto parse_res =
      this->ParseIntoCallableDecl(function.callable(), {decl.address}, decl);
  if (!parse_res.Succeeded()) {
    return parse_res.TakeError();
  }


  if (!function.has_frame()) {
    return std::string("All functions should have a frame");
  }
  const auto &frame = function.frame();

  decl.stack_depth = frame.frame_size();
  decl.ret_ptr_offset = frame.return_address_offset();
  decl.parameter_size = frame.parameter_size();
  decl.parameter_offset = frame.parameter_offset();

  decl.maximum_depth = decl.GetPointerDisplacement() + frame.max_frame_depth();

  for (auto &var : function.in_scope_vars()) {
    auto maybe_res = DecodeParameter(var);
    if (!maybe_res.Succeeded()) {
      LOG(ERROR) << "Couldn't decode live variable: " << var.name()
                 << " " + maybe_res.TakeError();
    } else {
      decl.in_scope_variables.push_back(maybe_res.TakeValue());
    }
  }

  if (decl.maximum_depth < decl.stack_depth) {
    LOG(ERROR)
        << "Analyzed max depth is smaller than the initial depth overriding";
    decl.maximum_depth = decl.stack_depth;
  }

  this->ParseCFGIntoFunction(function, decl);


  for (auto &ty_hint : function.type_hints()) {
    auto maybe_type = DecodeType(ty_hint.target_var().type());
    if (maybe_type.Succeeded()) {
      auto maybe_var =
          DecodeValueDecl(ty_hint.target_var().values(), maybe_type.TakeValue(),
                          "attempting to decode type hint value");
      if (maybe_var.Succeeded()) {
        decl.type_hints.push_back(
            {ty_hint.target_addr(), maybe_var.TakeValue()});
      }
    } else {
      LOG(ERROR) << "Failed to decode type for type hint";
    }
  }

  std::sort(decl.type_hints.begin(), decl.type_hints.end(),
            [](const TypeHint &hint_lhs, const TypeHint &hint_rhs) {
              return hint_lhs.target_addr < hint_rhs.target_addr;
            });

  auto link = function.func_linkage();

  if (link == specification::FUNCTION_LINKAGE_DECL) {
    decl.lift_as_decl = true;
  } else if (link == specification::FUNCTION_LINKAGE_EXTERNAL) {
    decl.lift_as_decl = true;
    decl.is_extern = true;
  } else {
    decl.lift_as_decl = false;
    decl.is_extern = false;
  }

  for (auto &[name, local] : function.local_variables()) {
    auto type_spec = DecodeType(local.type());
    if (!type_spec.Succeeded()) {
      return type_spec.Error();
    }

    auto value_decl =
        DecodeValueDecl(local.values(), type_spec.Value(), "local variable");
    if (!value_decl.Succeeded()) {
      return value_decl.Error();
    }

    decl.locals[name] = {value_decl.TakeValue(), name};
  }


  return decl;
}

void ProtobufTranslator::AddLiveValuesToBB(
    std::unordered_map<Uid, std::vector<ParameterDecl>> &map, Uid bb_uid,
    const ::google::protobuf::RepeatedPtrField<::specification::Parameter>
        &values) const {
  auto &v = map.insert({bb_uid, std::vector<ParameterDecl>()}).first->second;

  for (auto var : values) {
    auto param = DecodeParameter(var);
    if (!param.Succeeded()) {
      LOG(ERROR) << "Unable to decode live parameter " << param.TakeError();
    } else {
      v.push_back(param.TakeValue());
    }
  }
}

void ProtobufTranslator::ParseCFGIntoFunction(
    const ::specification::Function &obj, FunctionDecl &decl) const {
  for (const auto &blk : obj.blocks()) {
    std::unordered_set<Uid> tmp;
    for (auto o : blk.second.outgoing_blocks()) {
      tmp.insert({o});
    }
    CodeBlock nblk = {
        blk.second.address(),
        blk.second.size(),
        tmp,
        {blk.second.context_assignments().begin(),
         blk.second.context_assignments().end()},
        {blk.first},
    };
    decl.cfg.emplace(Uid{blk.first}, std::move(nblk));
  }


  for (auto &[blk_uid_, ctx] : obj.block_context()) {
    std::vector<OffsetDomain> stack_offsets_at_entry, stack_offsets_at_exit;
    std::vector<ConstantDomain> constant_values_at_entry,
        constant_values_at_exit;
    Uid blk_uid = {blk_uid_};
    auto blk = decl.cfg[blk_uid];
    auto symval_to_domains = [&](const specification::ValueMapping &symval,
                                 std::vector<OffsetDomain> &stack_offsets,
                                 std::vector<ConstantDomain> &constant_values) {
      if (!symval.has_target_value()) {
        LOG(FATAL) << "All equalities must have a target";
      }

      auto stackptr = arch->RegisterByName(arch->StackPointerRegisterName());
      if (!stackptr) {
        LOG(FATAL) << "No stack ptr";
      }

      auto target_type_spec = DecodeType(symval.target_value().type());
      if (!target_type_spec.Succeeded()) {
        LOG(ERROR) << "Failed to lift target type "
                   << target_type_spec.TakeError();
        return;
      }

      auto target_vdecl = DecodeValueDecl(
          symval.target_value().values(), target_type_spec.TakeValue(),
          "Unable to get value decl for target");

      if (!target_vdecl.Succeeded()) {
        LOG(ERROR) << "Failed to lift value " << target_vdecl.TakeError();
        return;
      }

      if (!symval.has_curr_val()) {
        LOG(FATAL) << "Mapping should have current value";
      }

      if (symval.curr_val().has_stack_disp()) {
        OffsetDomain reg_off;

        reg_off.stack_offset = symval.curr_val().stack_disp();
        reg_off.target_value = target_vdecl.TakeValue();

        stack_offsets.push_back(reg_off);
      } else if (symval.curr_val().has_constant()) {
        ConstantDomain const_val;

        const_val.target_value = target_vdecl.TakeValue();
        const_val.value = symval.curr_val().constant().value();
        const_val.should_taint_by_pc =
            symval.curr_val().constant().is_tainted_by_pc();

        DLOG(INFO) << "Adding global register override for "
                   << const_val.target_value.ordered_locs[0].reg->name << " "
                   << std::hex << const_val.value;
        constant_values.push_back(const_val);
      } else {
        LOG(FATAL) << symval.curr_val().GetTypeName()
                   << " is unimplemented for affine relations";
      }
    };

    for (auto &symval : ctx.symvals_at_entry()) {
      symval_to_domains(symval,
                        decl.stack_offsets_at_entry[blk_uid].affine_equalities,
                        decl.constant_values_at_entry[blk_uid]);
    }

    for (auto &symval : ctx.symvals_at_exit()) {
      symval_to_domains(symval,
                        decl.stack_offsets_at_exit[blk_uid].affine_equalities,
                        decl.constant_values_at_exit[blk_uid]);
    }

    this->AddLiveValuesToBB(decl.live_regs_at_entry, blk_uid,
                            ctx.live_at_entries());

    this->AddLiveValuesToBB(decl.live_regs_at_exit, blk_uid,
                            ctx.live_at_exits());
  }
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
  decl.spec_type = spec_type.TakeValue();

  auto llvm_type = type_translator.DecodeFromSpec(decl.spec_type);
  if (!llvm_type.Succeeded()) {
    std::stringstream ss;
    ss << "Cannot translate type for variable at address " << std::hex
       << decl.address << ": " << llvm_type.Error().message;
    return ss.str();
  }

  auto type = llvm_type.Value();
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

  if (obj.binary_address().has_ext_address()) {
    decl.binary_addr =
        RelAddr{obj.binary_address().ext_address().entry_vaddr(),
                obj.binary_address().ext_address().displacement()};
  } else {
    decl.binary_addr = obj.binary_address().internal_address();
  }


  return decl;
}

anvill::Result<TypeSpec, std::string> ProtobufTranslator::DecodeType(
    const ::specification::TypeSpec &obj,
    const std::unordered_map<std::int64_t, ::specification::TypeSpec> &map,
    const std::unordered_map<std::int64_t, std::string> &named_types) {
  if (obj.has_alias()) {
    auto alias = obj.alias();

    if (named_types.contains(alias)) {
      TypeSpec tname = TypeName(named_types.at(alias));
      return tname;
    }

    if (type_map.count(alias)) {
      return type_map[alias];
    }
    auto &type = type_map[alias];

    // The alias may not be present in the map in case of opaque pointers
    if (!map.count(alias)) {
      LOG(ERROR) << "No alias definition for " << obj.alias();
      return {BaseType::Void};
    }

    auto res = DecodeType(map.at(alias), map, named_types);
    if (!res.Succeeded()) {
      return res.TakeError();
    }
    type = res.TakeValue();
    return type;
  }
  if (obj.has_pointer()) {
    auto pointer = obj.pointer();
    TypeSpec pointee = BaseType::Void;
    if (pointer.has_pointee()) {
      auto maybe_pointee = DecodeType(pointer.pointee(), map, named_types);
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
    auto maybe_base = DecodeType(vector.base(), map, named_types);
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
    auto maybe_base = DecodeType(array.base(), map, named_types);
    if (!maybe_base.Succeeded()) {
      return maybe_base.Error();
    }
    return {std::make_shared<ArrayType>(maybe_base.Value(), array.size())};
  }
  if (obj.has_struct_()) {
    auto res = std::make_shared<StructType>();
    for (auto elem : obj.struct_().members()) {
      auto maybe_type = DecodeType(elem, map, named_types);
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
    auto maybe_ret = DecodeType(func.return_type(), map, named_types);
    if (!maybe_ret.Succeeded()) {
      return maybe_ret.Error();
    }
    res->return_type = std::move(maybe_ret.Value());
    res->is_variadic = func.is_variadic();
    for (auto arg : func.arguments()) {
      auto maybe_argtype = DecodeType(arg, map, named_types);
      if (!maybe_argtype.Succeeded()) {
        return maybe_argtype.Error();
      }
      res->arguments.push_back(std::move(maybe_argtype.Value()));
    }
  }

  return DecodeType(obj);
}

Result<std::monostate, std::string> ProtobufTranslator::DecodeTypeMap(
    const ::google::protobuf::Map<std::int64_t, ::specification::TypeSpec> &map,
    const ::google::protobuf::Map<std::int64_t, std::string> &names) {
  for (auto &[k, v] : map) {
    if (type_map.count(k)) {
      continue;
    }
    auto res =
        DecodeType(v, {map.begin(), map.end()}, {names.begin(), names.end()});

    if (!res.Succeeded()) {
      return res.Error();
    }


    if (names.contains(k)) {
      auto ty = this->type_translator.DecodeFromSpec(res.Value());
      if (!ty.Succeeded()) {
        return ty.Error().message;
      }

      if (auto *sty = llvm::dyn_cast<llvm::StructType>(ty.Value())) {


        std::string name = names.at(k);
        auto res = getOrCreateNamedStruct(this->context, name);
        res->setBody(sty->elements());
      }
      type_names[k] = names.at(k);
    } else {
      type_map[k] = res.Value();
    }
  }
  return std::monostate{};
}

}  // namespace anvill
