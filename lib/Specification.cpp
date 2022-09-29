/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "Specification.h"

#include <glog/logging.h>
#include <llvm/ADT/StringRef.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>
#include <specification.pb.h>

#include <algorithm>
#include <optional>
#include <sstream>

#include "Protobuf.h"
#include "anvill/Declarations.h"
#include "anvill/Specification.h"
#include "anvill/Type.h"

namespace anvill {

SpecificationImpl::~SpecificationImpl(void) {}

SpecificationImpl::SpecificationImpl(std::unique_ptr<const remill::Arch> arch_)
    : arch(std::move(arch_)),
      type_dictionary(*(arch->context)),
      type_translator(type_dictionary, arch.get()) {}

Result<std::vector<std::string>, std::string>
SpecificationImpl::ParseSpecification(
    const ::specification::Specification &spec) {
  ProtobufTranslator translator(type_translator, arch.get());
  std::vector<std::string> dec_err;
  for (auto &func : spec.functions()) {
    auto maybe_func = translator.DecodeFunction(func);
    if (!maybe_func.Succeeded()) {
      auto err = maybe_func.TakeError();
      dec_err.push_back(err);
    }
    auto func_obj = maybe_func.TakeValue();
    auto func_address = func_obj.address;
    if (address_to_function.count(func_address)) {
      std::stringstream ss;
      ss << "Duplicate function for address " << std::hex << func_address;
      return ss.str();
    }

    auto func_ptr = new FunctionDecl(std::move(func_obj));
    functions.emplace_back(func_ptr);
    address_to_function.emplace(func_address, func_ptr);
  }

  std::sort(functions.begin(), functions.end(),
            [](const FunctionDeclPtr &a, const FunctionDeclPtr &b) {
              return a->address < b->address;
            });


  for (auto &var : spec.global_variables()) {
    auto maybe_var = translator.DecodeGlobalVar(var);
    if (!maybe_var.Succeeded()) {
      auto err = maybe_var.TakeError();
      dec_err.push_back(err);
    }
    auto var_obj = maybe_var.TakeValue();
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

  if(!spec.has_overrides()) {
    return {"Spec has no control flow overrides"};
  }

  for(auto &jump : spec.overrides().jumps()) {
    Jump jmp{};
    jmp.stop = jump.stop();
    jmp.address = jump.address();
    jmp.targets = {jump.targets().begin(), jump.targets().end()};
    jumps.push_back(jmp);
  }

  for(auto &call : spec.overrides().calls()) {
    Call callspec{};
    callspec.stop = call.stop();
    callspec.address = call.address();
    if(call.has_return_address()) {
      callspec.return_address = call.return_address();
    }
    callspec.is_tailcall = call.is_tailcall();
    calls.push_back(callspec);
  }

  for(auto &ret : spec.overrides().returns()) {
    ControlFlowOverride overr;
    overr.stop = ret.stop();
    overr.address = ret.address();
    returns.push_back(overr);
  }

  for(auto &misc : spec.overrides().other()) {
    ControlFlowOverride overr;
    overr.stop = misc.stop();
    overr.address = misc.address();
    misc_overrides.push_back(overr);
  }

  // TODO(frabert): Parse everything else

  return dec_err;
}

Specification::~Specification(void) {}

Specification::Specification(std::shared_ptr<SpecificationImpl> impl_)
    : impl(std::move(impl_)) {}

// Return the architecture used by this specification.
std::shared_ptr<const remill::Arch> Specification::Arch(void) const {
  return std::shared_ptr<const remill::Arch>(impl, impl->arch.get());
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
    case ::specification::ARCH_X86: arch_name = remill::kArchX86; break;
    case ::specification::ARCH_X86_AVX: arch_name = remill::kArchX86_AVX; break;
    case ::specification::ARCH_X86_AVX512:
      arch_name = remill::kArchX86_AVX512;
      break;
    case ::specification::ARCH_AMD64: arch_name = remill::kArchAMD64; break;
    case ::specification::ARCH_AMD64_AVX:
      arch_name = remill::kArchAMD64_AVX;
      break;
    case ::specification::ARCH_ADM64_AVX512:
      arch_name = remill::kArchAMD64_AVX512;
      break;
    case ::specification::ARCH_AARCH64:
      arch_name = remill::kArchAArch64LittleEndian;
      break;
    case ::specification::ARCH_AARCH32:
      arch_name = remill::kArchAArch32LittleEndian;
      break;
    case ::specification::ARCH_SPARC32: arch_name = remill::kArchSparc32; break;
    case ::specification::ARCH_SPARC64: arch_name = remill::kArchSparc64; break;
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
    return {"Failed to parse specification"};
  }

  auto arch{GetArch(context, spec)};
  if (!arch.Succeeded()) {
    return arch.Error();
  }

  std::shared_ptr<SpecificationImpl> pimpl(
      new SpecificationImpl(arch.TakeValue()));

  auto maybe_warnings = pimpl->ParseSpecification(spec);

  if (!maybe_warnings.Succeeded()) {
    return maybe_warnings.TakeError();
  }

  auto warnings = maybe_warnings.TakeValue();
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

  std::shared_ptr<SpecificationImpl> pimpl(
      new SpecificationImpl(arch.TakeValue()));

  auto maybe_warnings = pimpl->ParseSpecification(spec);

  if (!maybe_warnings.Succeeded()) {
    return maybe_warnings.TakeError();
  }

  auto warnings = maybe_warnings.TakeValue();
  for (auto w : warnings) {
    LOG(ERROR) << w;
  }

  return Specification(std::move(pimpl));
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

// Call `cb` on each symbol in the spec, until `cb` returns `false`.
void Specification::ForEachSymbol(
    std::function<bool(std::uint64_t, const std::string &)> cb) const {
  for (const auto &[ea, name] : impl->symbols) {
    if (!cb(ea, name)) {
      return;
    }
  }
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

// Call `cb` on each control-flow target list, until `cb` returns `false`.
void Specification::ForEachControlFlowTargetList(
    std::function<bool(std::shared_ptr<const ControlFlowTargetList>)> cb)
    const {
  for (const auto &ent : impl->targets) {
    std::shared_ptr<const ControlFlowTargetList> ptr(impl, ent.get());
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
    std::function<bool(const ControlFlowOverride &)> cb) const {
  for (auto &ret : impl->returns) {
    if (!cb(ret)) {
      return;
    }
  }
}

void Specification::ForEachMiscOverride(
    std::function<bool(const ControlFlowOverride &)> cb) const {
  for (auto &misc : impl->misc_overrides) {
    if (!cb(misc)) {
      return;
    }
  }
}

}  // namespace anvill
