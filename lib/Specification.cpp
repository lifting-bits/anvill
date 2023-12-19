/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "Specification.h"

#include <glog/logging.h>
#include <google/protobuf/util/json_util.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>
#include <specification.pb.h>
#include <stddef.h>

#include <algorithm>
#include <optional>
#include <sstream>
#include <unordered_map>

#include "Protobuf.h"
#include "anvill/Declarations.h"
#include "anvill/Specification.h"
#include "anvill/Type.h"

namespace anvill {

SpecificationImpl::~SpecificationImpl(void) {}

SpecificationImpl::SpecificationImpl(std::unique_ptr<const remill::Arch> arch_,
                                     const std::string &image_name_,
                                     std::uint64_t image_base_)
    : arch(std::move(arch_)),
      image_name(image_name_),
      image_base(image_base_),
      type_dictionary(*(arch->context)),
      type_translator(type_dictionary, arch.get()) {}

Result<std::vector<std::string>, std::string>
SpecificationImpl::ParseSpecification(
    const ::specification::Specification &spec) {
  std::vector<std::string> dec_err;
  std::unordered_map<std::int64_t, TypeSpec> type_map;
  std::unordered_map<std::int64_t, std::string> type_names;
  ProtobufTranslator translator(type_translator, arch.get(), type_map,
                                type_names);
  auto map_res =
      translator.DecodeTypeMap(spec.type_aliases(), spec.type_names());
  if (!map_res.Succeeded()) {
    dec_err.push_back(map_res.Error());
  }
  for (auto &func : spec.functions()) {
    auto maybe_func = translator.DecodeFunction(func);
    if (!maybe_func.Succeeded()) {
      auto err = maybe_func.Error();
      dec_err.push_back(err);
      continue;
    }
    auto func_obj = maybe_func.Value();
    auto func_address = func_obj.address;
    if (address_to_function.count(func_address)) {
      std::stringstream ss;
      ss << "Duplicate function for address " << std::hex << func_address;
      return ss.str();
    }

    auto func_ptr = new FunctionDecl(std::move(func_obj));

    for (const auto &[uid, bb] : func_ptr->cfg) {
      if (uid_to_block.count(uid)) {
        std::stringstream ss;
        ss << "Duplicate block Uid: " << uid.value;
        return ss.str();
      }
      uid_to_block[uid] = &bb;
    }

    functions.emplace_back(func_ptr);
    address_to_function.emplace(func_address, func_ptr);
  }

  std::sort(functions.begin(), functions.end(),
            [](const FunctionDeclPtr &a, const FunctionDeclPtr &b) {
              return a->address < b->address;
            });

  for (auto &callsite : spec.callsites()) {
    auto maybe_cs = translator.DecodeCallsite(callsite);
    if (!maybe_cs.Succeeded()) {
      auto err = maybe_cs.Error();
      dec_err.push_back(err);
      continue;
    }
    auto cs_obj = maybe_cs.Value();
    std::pair<std::uint64_t, std::uint64_t> loc{cs_obj.function_address,
                                                cs_obj.address};

    if (loc_to_call_site.count(loc)) {
      std::stringstream ss;
      ss << "Duplicate callsite for address " << std::hex << loc.second
         << " in function " << std::hex << loc.first;
      return ss.str();
    }

    auto cs_ptr = new CallSiteDecl(std::move(cs_obj));
    call_sites.emplace_back(cs_ptr);
    loc_to_call_site.emplace(loc, cs_ptr);
  }

  std::sort(call_sites.begin(), call_sites.end(),
            [](const CallSiteDeclPtr &a, const CallSiteDeclPtr &b) {
              if (a->function_address < b->function_address) {
                return true;
              } else if (a->function_address > b->function_address) {
                return false;
              } else {
                return a->address < b->address;
              }
            });


  for (auto &var : spec.global_variables()) {
    auto maybe_var = translator.DecodeGlobalVar(var);
    if (!maybe_var.Succeeded()) {
      auto err = maybe_var.Error();
      dec_err.push_back(err);
      continue;
    }
    auto var_obj = maybe_var.Value();
    auto var_address = var_obj.address;
    if (address_to_function.count(var_address)) {
      std::stringstream ss;
      ss << "Duplicate variable for address " << std::hex << var_address;
      return ss.str();
    }

    auto var_ptr = new VariableDecl(std::move(var_obj));
    variables.emplace_back(var_ptr);
    address_to_var.emplace(var_address, var_ptr);
  }

  std::sort(variables.begin(), variables.end(),
            [](const VariableDeclPtr &a, const VariableDeclPtr &b) {
              return a->address < b->address;
            });

  for (auto &symbol : spec.symbols()) {
    auto name = symbol.name();
    auto address = symbol.address();

    if (name.empty()) {
      std::stringstream ss;
      ss << "Empty symbol name associated with address " << std::hex << address
         << " in the symbols list of program specification";
      return ss.str();
    }
    symbols.emplace(address, name);
  }

  for (auto &range : spec.memory_ranges()) {
    auto address = range.address();
    auto byte_perms = BytePermission::kReadable;
    if (range.is_writeable() && range.is_executable()) {
      byte_perms = BytePermission::kReadableWritableExecutable;
    } else if (range.is_writeable()) {
      byte_perms = BytePermission::kReadableWritable;
    } else if (range.is_executable()) {
      byte_perms = BytePermission::kReadableExecutable;
    }

    for (size_t j = 0; j < range.values().size(); ++j) {
      auto byte_address = address + j;
      auto &ent = memory[byte_address];
      if (BytePermission::kUnknown != ent.second) {
        std::stringstream ss;
        ss << "Byte at address " << std::hex << byte_address
           << " in memory range starting at address " << address
           << " was previously mapped";
        return ss.str();
      }

      ent.first = range.values()[j];
      ent.second = byte_perms;
    }
  }

  if (!spec.has_overrides()) {
    return {"Spec has no control flow overrides"};
  }

  for (auto &jump : spec.overrides().jumps()) {
    Jump jmp{};
    jmp.stop = jump.stop();
    jmp.address = jump.address();
    for (auto &target : jump.targets()) {
      JumpTarget jmp_target;
      jmp_target.address = target.address();
      jmp.targets.push_back(jmp_target);
    }
    std::sort(
        jmp.targets.begin(), jmp.targets.end(),
        [](const auto &a, const auto &b) { return a.address < b.address; });
    jumps.push_back(jmp);
    const auto res = control_flow_overrides.emplace(jmp.address, jmp);
    CHECK(res.second);
  }
  std::sort(jumps.begin(), jumps.end(),
            [](const auto &a, const auto &b) { return a.address < b.address; });

  for (auto &call : spec.overrides().calls()) {
    Call callspec{};
    callspec.stop = call.stop();
    callspec.is_noreturn = call.noreturn();
    callspec.address = call.address();
    if (call.has_return_address()) {
      callspec.return_address = call.return_address();
    }
    if (call.has_target_address()) {
      callspec.target_address = call.target_address();
    }
    callspec.is_tailcall = call.is_tailcall();
    calls.push_back(callspec);
    const auto res = control_flow_overrides.emplace(callspec.address, callspec);
    CHECK(res.second);
  }
  std::sort(calls.begin(), calls.end(),
            [](const auto &a, const auto &b) { return a.address < b.address; });

  for (auto &ret : spec.overrides().returns()) {
    Return overr;
    overr.stop = ret.stop();
    overr.address = ret.address();
    returns.push_back(overr);
    const auto res = control_flow_overrides.emplace(overr.address, overr);
    CHECK(res.second);
  }
  std::sort(returns.begin(), returns.end(),
            [](const auto &a, const auto &b) { return a.address < b.address; });

  for (auto &misc : spec.overrides().others()) {
    Misc overr;
    overr.stop = misc.stop();
    overr.address = misc.address();
    misc_overrides.push_back(overr);
    const auto res = control_flow_overrides.emplace(overr.address, overr);
    CHECK(res.second);
  }
  std::sort(misc_overrides.begin(), misc_overrides.end(),
            [](const auto &a, const auto &b) { return a.address < b.address; });

  required_globals = {spec.required_globals().begin(),
                      spec.required_globals().end()};

  for (const auto &[_k, v] : spec.type_names()) {
    this->named_types.push_back(v);
  }

  for (const auto &[id, type] : spec.type_aliases()) {
    auto maybe_ty = translator.DecodeType(type);
    CHECK(maybe_ty.Succeeded());
    auto ty_ptr = new TypeSpec(std::move(maybe_ty.Value()));
    type_id_to_type.emplace(id, ty_ptr);
  }

  return dec_err;
}

Specification::~Specification(void) {}

Specification::Specification(std::shared_ptr<SpecificationImpl> impl_)
    : impl(std::move(impl_)) {}

// Return the architecture used by this specification.
std::shared_ptr<const remill::Arch> Specification::Arch(void) const {
  return std::shared_ptr<const remill::Arch>(impl, impl->arch.get());
}

// Return the architecture used by this specification.
const std::string &Specification::ImageName(void) const {
  return impl->image_name;
}

// Return the architecture used by this specification.
std::uint64_t Specification::ImageBase(void) const {
  return impl->image_base;
}

// Return the type dictionary used by this specification.
const ::anvill::TypeDictionary &Specification::TypeDictionary(void) const {
  return impl->type_dictionary;
}

// Return the type provider used by this specification.
const ::anvill::TypeTranslator &Specification::TypeTranslator(void) const {
  return impl->type_translator;
}

using ArchPtr = std::unique_ptr<const remill::Arch>;

static anvill::Result<ArchPtr, std::string>
GetArch(llvm::LLVMContext &context,
        const ::specification::Specification &spec) {
  std::stringstream ss;
  remill::ArchName arch_name = remill::kArchInvalid;
  remill::OSName os_name = remill::kOSInvalid;

  switch (spec.arch()) {
    default: return {"Invalid/unrecognized architecture"};
    case ::specification::ARCH_X86: arch_name = remill::kArchX86_AVX; break;
    case ::specification::ARCH_X86_AVX: arch_name = remill::kArchX86_AVX; break;
    case ::specification::ARCH_X86_AVX512:
      arch_name = remill::kArchX86_AVX512;
      break;
    case ::specification::ARCH_AMD64: arch_name = remill::kArchAMD64_AVX; break;
    case ::specification::ARCH_AMD64_AVX:
      arch_name = remill::kArchAMD64_AVX;
      break;
    case ::specification::ARCH_ADM64_AVX512:
      arch_name = remill::kArchAMD64_AVX512;
      break;
    case ::specification::ARCH_AARCH64:
      arch_name = remill::kArchAArch64LittleEndian_SLEIGH;
      break;
    case ::specification::ARCH_AARCH32:
      arch_name = remill::kArchAArch32LittleEndian;
      break;
    case ::specification::ARCH_SPARC32:
      arch_name = remill::kArchSparc32_SLEIGH;
      break;
    case ::specification::ARCH_SPARC64: arch_name = remill::kArchSparc64; break;
    case ::specification::ARCH_PPC: arch_name = remill::kArchPPC; break;
  }

  switch (spec.operating_system()) {
    default: return {"Invalid/unrecognized operating system"};
    case ::specification::OS_LINUX: os_name = remill::kOSLinux; break;
    case ::specification::OS_MACOS: os_name = remill::kOSmacOS; break;
    case ::specification::OS_WINDOWS: os_name = remill::kOSWindows; break;
    case ::specification::OS_SOLARIS: os_name = remill::kOSSolaris; break;
  }

  // Get a unique pointer to a remill architecture object. The architecture
  // object knows how to deal with everything for this specific architecture,
  // such as semantics, register,  etc.
  auto arch = remill::Arch::Build(&context, os_name, arch_name);
  if (!arch) {
    ss << "Invalid architecture/operating system combination "
       << remill::GetArchName(arch_name) << '/' << remill::GetOSName(os_name)
       << " in program specification";
    return ss.str();
  }
  return std::move(arch);
}

anvill::Result<Specification, std::string>
Specification::DecodeFromPB(llvm::LLVMContext &context, const std::string &pb) {
  ::specification::Specification spec;
  if (!spec.ParseFromString(pb)) {
    auto status = google::protobuf::util::JsonStringToMessage(pb, &spec);
    if (!status.ok()) {
      return {"Failed to parse specification"};
    }
  }

  auto arch{GetArch(context, spec)};
  if (!arch.Succeeded()) {
    return arch.Error();
  }

  const auto &image_name = spec.image_name();
  auto image_base = spec.image_base();

  std::shared_ptr<SpecificationImpl> pimpl(
      new SpecificationImpl(arch.TakeValue(), image_name, image_base));

  auto maybe_warnings = pimpl->ParseSpecification(spec);

  if (!maybe_warnings.Succeeded()) {
    return maybe_warnings.Error();
  }

  auto warnings = maybe_warnings.Value();
  for (auto w : warnings) {
    LOG(ERROR) << w;
  }

  return Specification(std::move(pimpl));
}

anvill::Result<Specification, std::string>
Specification::DecodeFromPB(llvm::LLVMContext &context, std::istream &pb) {
  ::specification::Specification spec;

  if (!spec.ParseFromIstream(&pb)) {
    return {"Failed to parse specification"};
  }

  auto arch{GetArch(context, spec)};
  if (!arch.Succeeded()) {
    return arch.Error();
  }

  const auto &image_name = spec.image_name();
  auto image_base = spec.image_base();


  std::shared_ptr<SpecificationImpl> pimpl(
      new SpecificationImpl(arch.TakeValue(), image_name, image_base));

  auto maybe_warnings = pimpl->ParseSpecification(spec);

  if (!maybe_warnings.Succeeded()) {
    return maybe_warnings.Error();
  }

  auto warnings = maybe_warnings.Value();
  for (auto w : warnings) {
    LOG(ERROR) << w;
  }

  return Specification(std::move(pimpl));
}

// Return the call site at a given function address, instruction address pair, or an empty `shared_ptr`.
std::shared_ptr<const CallSiteDecl> Specification::CallSiteAt(
    const std::pair<std::uint64_t, std::uint64_t> &loc) const {
  auto it = impl->loc_to_call_site.find(loc);
  if (it != impl->loc_to_call_site.end()) {
    return {impl, it->second};
  }
  return {};
}

// Return the function beginning at `address`, or an empty `shared_ptr`.
std::shared_ptr<const FunctionDecl>
Specification::FunctionAt(std::uint64_t address) const {
  auto it = impl->address_to_function.find(address);
  if (it != impl->address_to_function.end()) {
    return std::shared_ptr<const FunctionDecl>(impl, it->second);
  } else {
    return {};
  }
}

// Return the block with `uid`, or an empty `shared_ptr`.
std::shared_ptr<const CodeBlock> Specification::BlockAt(Uid uid) const {
  auto it = impl->uid_to_block.find(uid);
  if (it != impl->uid_to_block.end()) {
    return std::shared_ptr<const CodeBlock>(impl, it->second);
  } else {
    return {};
  }
}

// Return the global variable beginning at `address`, or an empty `shared_ptr`.
std::shared_ptr<const VariableDecl>
Specification::VariableAt(std::uint64_t address) const {
  auto it = impl->address_to_var.find(address);
  if (it != impl->address_to_var.end()) {
    if (it->second->address == address) {
      return std::shared_ptr<const VariableDecl>(impl, it->second);
    }
  }
  return {};
}

// Return the global variable containing `address`, or an empty `shared_ptr`.
std::shared_ptr<const VariableDecl>
Specification::VariableContaining(std::uint64_t address) const {
  auto it = impl->address_to_var.find(address);
  if (it != impl->address_to_var.end()) {
    return std::shared_ptr<const VariableDecl>(impl, it->second);
  } else {
    return {};
  }
}

std::shared_ptr<const TypeSpec> Specification::TypeAt(uint64_t id) const {
  auto type_it = impl->type_id_to_type.find(id);
  if (type_it != impl->type_id_to_type.end()) {
    return std::shared_ptr<const TypeSpec>(impl, type_it->second);
  }

  return {};
}

// Call `cb` on each symbol in the spec, until `cb` returns `false`.
void Specification::ForEachSymbol(
    std::function<bool(std::uint64_t, const std::string &)> cb) const {
  for (const auto &[ea, name] : impl->symbols) {
    if (!cb(ea, name)) {
      return;
    }
  }
}

SpecBlockContexts::SpecBlockContexts(const Specification &spec) {
  spec.ForEachFunction([this](std::shared_ptr<const FunctionDecl> decl) {
    decl->AddBBContexts(this->contexts);
    funcs[decl->address] = decl;
    return true;
  });
}

std::optional<std::reference_wrapper<const BasicBlockContext>>
SpecBlockContexts::GetBasicBlockContextForUid(Uid uid) const {
  auto cont = this->contexts.find(uid);
  if (cont == this->contexts.end()) {
    return std::nullopt;
  }

  return std::optional<std::reference_wrapper<const BasicBlockContext>>{
      std::cref(cont->second)};
}

const FunctionDecl &
SpecBlockContexts::GetFunctionAtAddress(uint64_t addr) const {
  return *funcs.at(addr);
}

// Call `cb` on each function in the spec, until `cb` returns `false`.
void Specification::ForEachFunction(
    std::function<bool(std::shared_ptr<const FunctionDecl>)> cb) const {
  for (const auto &ent : impl->functions) {
    std::shared_ptr<const FunctionDecl> ptr(impl, ent.get());
    if (!cb(std::move(ptr))) {
      return;
    }
  }
}

// Call `cb` on each variable in the spec, until `cb` returns `false`.
void Specification::ForEachVariable(
    std::function<bool(std::shared_ptr<const VariableDecl>)> cb) const {
  for (const auto &ent : impl->variables) {
    std::shared_ptr<const VariableDecl> ptr(impl, ent.get());
    if (!cb(std::move(ptr))) {
      return;
    }
  }
}

// Call `cb` on each call site in the spec, until `cb` returns `false`.
void Specification::ForEachCallSite(
    std::function<bool(std::shared_ptr<const CallSiteDecl>)> cb) const {
  for (const auto &ent : impl->call_sites) {
    std::shared_ptr<const CallSiteDecl> ptr(impl, ent.get());
    if (!cb(std::move(ptr))) {
      return;
    }
  }
}


// Call `cb` on each control-flow redirection, until `cb` returns `false`.
void Specification::ForEachControlFlowRedirect(
    std::function<bool(std::uint64_t, std::uint64_t)> cb) const {
  for (auto [from, to] : impl->redirections) {
    if (!cb(from, to)) {
      return;
    }
  }
}

void Specification::ForEachJump(std::function<bool(const Jump &)> cb) const {
  for (auto &jump : impl->jumps) {
    if (!cb(jump)) {
      return;
    }
  }
}

void Specification::ForEachCall(std::function<bool(const Call &)> cb) const {
  for (auto &call : impl->calls) {
    if (!cb(call)) {
      return;
    }
  }
}

void Specification::ForEachReturn(
    std::function<bool(const Return &)> cb) const {
  for (auto &ret : impl->returns) {
    if (!cb(ret)) {
      return;
    }
  }
}

void Specification::ForEachMiscOverride(
    std::function<bool(const Misc &)> cb) const {
  for (auto &misc : impl->misc_overrides) {
    if (!cb(misc)) {
      return;
    }
  }
}

const std::unordered_set<std::string> &
Specification::GetRequiredGlobals() const {
  return impl->required_globals;
}

}  // namespace anvill
