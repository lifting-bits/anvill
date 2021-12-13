/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "Specification.h"

#include <algorithm>
#include <sstream>

#include <anvill/JSON.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/JSON.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Util.h>
#include <remill/BC/Compat/Error.h>
#include <remill/OS/OS.h>

namespace anvill {

SpecificationImpl::~SpecificationImpl(void) {}

SpecificationImpl::SpecificationImpl(std::unique_ptr<const remill::Arch> arch_)
    : arch(std::move(arch_)),
      type_dictionary(*(arch->context)),
      type_translator(type_dictionary, arch.get()) {}

bool SpecificationImpl::ParseRange(const llvm::json::Object *obj,
                                   std::stringstream &ss) {

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    ss << "Missing address in memory range specification";
    return false;
  }

  uint64_t address = static_cast<uint64_t>(*maybe_ea);
  bool is_writeable = false;
  bool is_executable = false;

  auto perm = obj->getBoolean("is_writeable");
  if (perm) {
    is_writeable = *perm;
  }

  perm = obj->getBoolean("is_executable");
  if (perm) {
    is_executable = *perm;
  }

  auto byte_perms = BytePermission::kReadable;
  if (is_writeable && is_executable) {
    byte_perms = BytePermission::kReadableWritableExecutable;
  } else if (is_writeable) {
    byte_perms = BytePermission::kReadableWritable;
  } else if (is_executable) {
    byte_perms = BytePermission::kReadableExecutable;
  }

  auto maybe_bytes = obj->getString("data");
  if (!maybe_bytes) {
    ss << "Missing byte string in memory range starting at address "
       << std::hex << address << " of program specification";
    return false;
  }

  const llvm::StringRef &bytes = *maybe_bytes;
  if (bytes.size() % 2) {
    ss << "Length of byte string in memory range starting at address "
       << std::hex << address << " must have an even number of characters";
    return false;
  }

  // Parse out the hex-encoded byte sequence.
  for (auto i = 0ul, j = 0ul; i < bytes.size(); i += 2, ++j) {
    char nibbles[3] = {bytes[i], bytes[i + 1], '\0'};
    char *parsed_to = nullptr;
    auto byte_val = strtol(nibbles, &parsed_to, 16);

    if (parsed_to != &(nibbles[2])) {
      ss << "Invalid hex byte value '" << nibbles
         << "' in memory range starting at address " << std::hex << address;
      return false;
    }

    auto byte_address = address + j;
    auto &ent = memory[byte_address];
    if (BytePermission::kUnknown != ent.second) {
      ss << "Byte at address " << std::hex << byte_address
         << " in memory range starting at address " << address
         << " was previously mapped";
      return false;
    }

    ent.first = byte_val;
    ent.second = byte_perms;
  }

  return true;
}

bool SpecificationImpl::ParseControlFlowRedirection(
    const llvm::json::Array &redirection_list,
    std::stringstream &ss) {

  auto index{0u};

  for (const llvm::json::Value &list_entry : redirection_list) {
    auto address_pair = list_entry.getAsArray();
    if (!address_pair) {
      ss << "Non-list entry in 'control_flow_redirections' list of program "
         << "specification";
      return false;
    }

    if (address_pair->size() != 2U) {
      ss << index << "th entry in 'control_flow_redirections' "
         << "list of program specification must be a pair of integers";
      return false;
    }

    const auto &source_address_obj = address_pair->operator[](0);
    auto opt_source_address = source_address_obj.getAsInteger();
    if (!opt_source_address) {
      ss << "First value of " << index << "th entry in "
         << "'control_flow_redirections' list of program specification "
         << "must be an integer";
      return false;
    }

    const auto &dest_address_obj = address_pair->operator[](1);
    auto opt_dest_address = dest_address_obj.getAsInteger();
    if (!opt_source_address) {
      ss << "Second value of " << index << "th entry in "
         << "'control_flow_redirections' list of program specification "
         << "must be an integer";
      return false;
    }

    auto source_address = static_cast<uint64_t>(opt_source_address.getValue());
    auto dest_address = static_cast<uint64_t>(opt_dest_address.getValue());

    if (source_address == dest_address) {
      ss << index << "th entry in the 'control_flow_redirections' list of "
         << "program specification cannot redirect and address (" << std::hex
         << source_address << ") to itself";
      return false;
    }

    if (redirections.count(source_address)) {
      ss << "Cannot re-define a control-flow redirection on source address "
         << std::hex << source_address << " in " << index
         << "th entry of 'control_flow_redirections' list of program "
         << "specification";
      return false;
    }

    redirections.emplace(source_address, dest_address);

    ++index;
  }

  return true;
}

bool SpecificationImpl::ParseControlFlowTargets(
    const llvm::json::Array &ctrl_flow_target_list, std::stringstream &ss) {

  auto index{0u};

  for (const llvm::json::Value &list_entry : ctrl_flow_target_list) {
    auto entry_as_obj = list_entry.getAsObject();
    if (!entry_as_obj) {
      ss << "Non-object " << index << "th entry of 'control_flow_targets' "
         << "list of program specification";
      return false;
    }

    if (entry_as_obj->find("source") == entry_as_obj->end()) {
      ss << "Missing 'source' value in " << index
         << "th entry of 'control_flow_targets' list of program specification";
      return false;
    }

    auto maybe_source = entry_as_obj->getInteger("source");
    if (!maybe_source.hasValue()) {
      ss << "Non-integer 'source' value in " << index
         << "th entry of 'control_flow_targets' list of program specification";
      return false;
    }

    const auto source_address = static_cast<uint64_t>(maybe_source.getValue());

    std::unique_ptr<ControlFlowTargetList> target_list(
        new ControlFlowTargetList);
    target_list->address = source_address;

    if (address_to_targets.count(source_address)) {
      ss << "Source address of " << index
         << "th entry of 'control_flow_targets' list (source address: "
         << std::hex << source_address
         << ") already has a corresponding entry in the program specification";
      return false;
    }

    if (entry_as_obj->find("is_complete") == entry_as_obj->end()) {
      ss << "Missing 'is_complete' value in " << index
         << "th entry of 'control_flow_targets' list (source address: "
         << std::hex << source_address << ") of program specification";
      return false;
    }

    auto maybe_complete = entry_as_obj->getBoolean("is_complete");
    if (!maybe_complete.hasValue()) {
      ss << "Non-Boolean 'is_complete' value in " << index
         << "th entry of 'control_flow_targets' list (source address: "
         << std::hex << source_address << ") of program specification";
      return false;
    }

    target_list->is_complete = maybe_complete.getValue();

    if (entry_as_obj->find("destinations") == entry_as_obj->end()) {
      ss << "Missing 'destinations' list in " << index
         << "th entry of 'control_flow_targets' list (source address: "
         << std::hex << source_address << ") of program specification";
      return false;
    }

    auto destination_list = entry_as_obj->getArray("destinations");
    if (!destination_list) {
      ss << "Non-array 'destinations' value in " << index
         << "th entry of 'control_flow_targets' list (source address: "
         << std::hex << source_address << ") of program specification";
      return false;
    }

    auto sub_index{0u};
    for (const auto &destination_list_entry : *destination_list) {
      auto maybe_destination = destination_list_entry.getAsInteger();
      if (!maybe_destination.hasValue()) {
        ss << "Non-integer value in " << sub_index
           << "th entry of 'destinations' list of " << index
           << "th entry of 'control_flow_targets' list (source address: "
           << std::hex << source_address << ") of program specification";
        return false;
      }

      auto destination = maybe_destination.getValue();
      target_list->target_addresses.insert(destination);

      ++sub_index;
    }

    if (!sub_index) {
      ss << "Empty 'destinations' list in " << index
         << "th entry of 'control_flow_targets' list (source address: "
         << std::hex << source_address << ") of program specification";
      return false;
    }

    address_to_targets.emplace(source_address, target_list.get());
    targets.emplace_back(std::move(target_list));

    ++index;
  }

  std::sort(targets.begin(), targets.end(),
            [] (const ControlFlowTargetListPtr &a,
                const ControlFlowTargetListPtr &b) {
              return a->address < b->address;
            });

  return true;
}

const llvm::json::Object *SpecificationImpl::ParseSpecification(
    const llvm::json::Object *spec, std::stringstream &ss) {

  JSONTranslator translator(type_translator, arch.get());

  if (auto funcs = spec->getArray("functions")) {
    auto index{0u};
    for (const llvm::json::Value &func : *funcs) {
      if (auto func_obj = func.getAsObject()) {
        auto maybe_func = translator.DecodeFunction(func_obj);
        if (maybe_func.Failed()) {
          auto err = maybe_func.TakeError();
          ss << "Unable to decode " << index
             << "th function in 'functions' list of program specification: "
             << err.message;

          // Make sure we return non-`nullptr` on failure.
          return err.object ? err.object : func_obj;

        } else {
          auto func = maybe_func.TakeValue();
          auto func_address = func.address;
          if (address_to_function.count(func_address)) {
            ss << "Duplicate function for address " << std::hex << func_address
               << std::dec << " at " << index
               << "th entry of 'functions' list of program specification";
            return func_obj;
          }

          auto func_ptr = new FunctionDecl(std::move(func));
          functions.emplace_back(func_ptr);
          address_to_function.emplace(func_address, func_ptr);
        }
      } else {
        ss << index << "th entry of 'functions' list of program specification "
           << "is not an object";
        return spec;
      }
      ++index;
    }

    std::sort(functions.begin(), functions.end(),
              [] (const FunctionDeclPtr &a, const FunctionDeclPtr &b) {
                return a->address < b->address;
              });

  } else if (spec->find("functions") != spec->end()) {
    ss << "Non-JSON array value for 'functions' in program specification";
    return spec;
  }


  if (auto call_sites_list = spec->getArray("call_sites")) {
    auto index{0u};
    for (const llvm::json::Value &cs : *call_sites_list) {
      if (auto cs_obj = cs.getAsObject()) {
        auto maybe_cs = translator.DecodeCallSite(cs_obj);
        if (maybe_cs.Failed()) {
          auto err = maybe_cs.TakeError();
          ss << "Unable to decode " << index
             << "th call site in 'call_sites' list of program specification: "
             << err.message;

          // Make sure we return non-`nullptr` on failure.
          return err.object ? err.object : cs_obj;

        } else {
          auto func = maybe_cs.TakeValue();
          auto address = func.address;
          auto func_address = func.function_address;
          std::pair<std::uint64_t, std::uint64_t> loc{func_address, address};
          if (loc_to_call_site.count(loc)) {
            ss << "Duplicate call site for address " << std::hex << address
               << " in function at address " << func_address
               << std::dec << " at " << index
               << "th entry of 'call_sites' list of program specification";
            return cs_obj;
          }

          auto cs_ptr = new CallSiteDecl(std::move(func));
          call_sites.emplace_back(cs_ptr);
          loc_to_call_site.emplace(std::move(loc), cs_ptr);
        }
      } else {
        ss << index << "th entry of 'call_sites' list of program specification "
           << "is not an object";
        return spec;
      }
      ++index;
    }

    std::sort(call_sites.begin(), call_sites.end(),
              [] (const CallSiteDeclPtr &a, const CallSiteDeclPtr &b) {
                if (a->function_address < b->function_address) {
                  return true;
                } else if (a->function_address > b->function_address) {
                  return false;
                } else {
                  return a->address < b->address;
                }
              });

  } else if (spec->find("call_sites") != spec->end()) {
    ss << "Non-JSON array value for 'call_sites' in program specification";
    return spec;
  }

  if (auto redirection_list = spec->getArray("control_flow_redirections")) {
    if (!ParseControlFlowRedirection(*redirection_list, ss)) {
      return spec;
    }

  } else if (spec->find("control_flow_redirections") != spec->end()) {
    ss << "Non-JSON array value for 'control_flow_redirections' in "
       << "program specification";
    return spec;
  }

  if (auto ctrl_flow_targets = spec->getArray("control_flow_targets")) {
    if (!ParseControlFlowTargets(*ctrl_flow_targets, ss)) {
      return spec;
    }

  } else if (spec->find("control_flow_targets") != spec->end()) {
    ss << "Non-JSON array value for 'control_flow_targets' in program "
       << "specification";
    return spec;
  }

  if (auto vars = spec->getArray("variables")) {
    auto index{0u};
    const llvm::DataLayout &dl = type_translator.DataLayout();
    for (const llvm::json::Value &var : *vars) {
      if (auto var_obj = var.getAsObject()) {
        auto maybe_var = translator.DecodeGlobalVar(var_obj);
        if (maybe_var.Failed()) {
          auto err = maybe_var.TakeError();
          ss << "Unable to decode " << index
             << "th variable in 'variables' list of program specification: "
             << err.message;

          // Make sure we return non-`nullptr` on failure.
          return err.object ? err.object : var_obj;

        } else {
          auto var_ptr = new VariableDecl(maybe_var.TakeValue());
          variables.emplace_back(var_ptr);

          auto size = dl.getTypeAllocSize(var_ptr->type).getKnownMinValue();
          for (auto i = 0ull; i < size; ++i) {
            (void) address_to_var.emplace(var_ptr->address + i, var_ptr);

//            auto [it, added] =
//            if (!added) {
//              ss << "Variable starting at " << std::hex << var_ptr->address
//                 << " (the " << index << "th entry in 'variables' list) "
//                 << "overlaps with the variable at " << it->second->address
//                 << " in program specification";
//              return var_obj;
//            }
          }
        }
      } else {
        ss << index << "th entry of 'variables' list of program specification "
           << "is not an object";
        return spec;
      }
      ++index;
    }

    std::sort(variables.begin(), variables.end(),
              [] (const VariableDeclPtr &a, const VariableDeclPtr &b) {
                return a->address < b->address;
              });

  } else if (spec->find("variables") != spec->end()) {
    ss << "Non-JSON array value for 'variables' in program specification";
    return spec;
  }

  // Map in the memory needed for this decompilation.
  if (auto ranges = spec->getArray("memory")) {
    auto index{0u};
    for (const llvm::json::Value &range : *ranges) {
      if (auto range_obj = range.getAsObject()) {
        if (!ParseRange(range_obj, ss)) {
          return range_obj;
        }
      } else {
        ss << "Non-JSON object in " << index
           << "th entry of 'memory' list of program specification";
        return spec;
      }
      ++index;
    }
  } else if (spec->find("memory") != spec->end()) {
    ss << "Non-JSON array value for 'memory' in program specification";
    return spec;
  }

  // Map in the symbols.
  if (auto symbols_array = spec->getArray("symbols")) {
    auto index{0u};
    for (const llvm::json::Value &maybe_ea_name : *symbols_array) {
      if (auto ea_name = maybe_ea_name.getAsArray(); ea_name) {
        if (ea_name->size() != 2u) {
          ss << "Each entry in 'symbols' list of program specification "
             << "must have exactly two values";
          return spec;
        }

        auto &maybe_ea = ea_name->operator[](0u);
        auto &maybe_name = ea_name->operator[](1u);

        if (auto ea_ = maybe_ea.getAsInteger()) {
          const auto ea = static_cast<uint64_t>(ea_.getValue());
          if (auto name = maybe_name.getAsString(); name) {
            if (name->empty()) {
              ss << "Empty symbol name associated with address " << std::hex
                 << ea << " in the " << index << "th entry of the 'symbols'"
                 << " list of program specification";
              return spec;
            } else {
              symbols.emplace(ea, name->str());
            }
          } else {
            ss << "Second value, associated with address " << std::hex << ea
               << " in the " << index << "th entry of the 'symbols' list of"
               << " program specification must be a string";
            return spec;
          }
        } else {
          ss << "First value of every entry in the 'symbols' list of a "
             << "program specification must be an integer; " << index
             << "th entry's first vale is not an integer";
          return spec;
        }
      } else {
        ss << "Expected list entries (pairs) inside of 'symbols' list of "
           << "program specification; " << index << "th entry is not a list";
        return spec;
      }

      ++index;
    }
  } else if (spec->find("symbols") != spec->end()) {
    ss << "Non-JSON array value for 'symbols' in program specification";
    return spec;
  }

  return nullptr;
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

// Try to create a program from a JSON specification. Returns a string error
// if something went wrong.
anvill::Result<Specification, JSONDecodeError> Specification::DecodeFromJSON(
    llvm::LLVMContext &context, const llvm::json::Value &json) {
  const auto spec = json.getAsObject();
  if (!spec) {
    return JSONDecodeError("Could not interpret json value as an object");
  }

  std::stringstream ss;
  remill::ArchName arch_name = remill::kArchInvalid;
  remill::OSName os_name = remill::kOSInvalid;

  // Take the architecture name out of the JSON spec.
  if (auto maybe_arch = spec->getString("arch")) {
    auto arch_str = maybe_arch->str();
    arch_name = remill::GetArchName(arch_str);
    if (arch_name == remill::kArchInvalid) {
      ss << "Invalid/unrecognized architecture name: " << arch_str;
      return JSONDecodeError(ss.str());
    }
  } else {
    return JSONDecodeError("Missing 'arch' field in program specification");
  }

  // Take the OS name out of the JSON spec.
  if (auto maybe_os = spec->getString("os")) {
    auto os_str = maybe_os->str();
    os_name = remill::GetOSName(os_str);
    if (os_name == remill::kOSInvalid) {
      ss << "Invalid/unrecognized operating system name: " << os_str;
      return JSONDecodeError(ss.str());
    }
  } else {
    return JSONDecodeError("Missing 'os' field in program specification");
  }

  // Get a unique pointer to a remill architecture object. The architecture
  // object knows how to deal with everything for this specific architecture,
  // such as semantics, register,  etc.
  auto arch = remill::Arch::Build(&context, os_name, arch_name);
  if (!arch) {
    ss << "Invalid architecture/operating system combination "
       << remill::GetArchName(arch_name) << '/'
       << remill::GetOSName(os_name) << " in program specification";
    return JSONDecodeError(ss.str());
  }

  std::shared_ptr<SpecificationImpl> pimpl(
      new SpecificationImpl(std::move(arch)));

  if (auto err_obj = pimpl->ParseSpecification(spec, ss)) {
    return JSONDecodeError(ss.str(), err_obj);
  }

  return Specification(std::move(pimpl));
}

// Try to encode the specification into JSON.
anvill::Result<llvm::json::Object, JSONEncodeError>
Specification::EncodeToJSON(void) {

  JSONTranslator translator(impl->type_translator, impl->arch.get());

  llvm::json::Array functions;
  llvm::json::Array call_sites;
  llvm::json::Array variables;
  llvm::json::Array symbols;
  llvm::json::Array memory;
  llvm::json::Array redirects;
  llvm::json::Array targets;

  for (const auto &func : impl->functions) {
    Result<llvm::json::Object, JSONEncodeError> maybe_func =
        translator.Encode(*func);
    if (maybe_func.Failed()) {
      return maybe_func.TakeError();
    } else {
      functions.emplace_back(maybe_func.TakeValue());
    }
  }

  for (const auto &cs : impl->call_sites) {
    Result<llvm::json::Object, JSONEncodeError> maybe_cs =
        translator.Encode(*cs);
    if (maybe_cs.Failed()) {
      return maybe_cs.TakeError();
    } else {
      call_sites.emplace_back(maybe_cs.TakeValue());
    }
  }

  for (const auto &var : impl->variables) {
    Result<llvm::json::Object, JSONEncodeError> maybe_var =
        translator.Encode(*var);
    if (maybe_var.Failed()) {
      return maybe_var.TakeError();
    } else {
      variables.emplace_back(maybe_var.TakeValue());
    }
  }

  for (const auto &[address, name] : impl->symbols) {
    if (name.empty()) {
      std::stringstream ss;
      ss << "Empty name for symbol at address " << std::hex << address;
      return JSONEncodeError(ss.str());
    }

    llvm::json::Array entry;
    entry.push_back(static_cast<int64_t>(address));
    entry.push_back(name);
    symbols.emplace_back(std::move(entry));
  }

  struct Range {
    std::string hex_bytes;
    uint64_t begin_address{};
    bool is_writeable{false};
    bool is_executable{false};
  };

  // Merge the byte-granularity memory representation into a range-based
  // representation.
  std::vector<Range> ranges;
  for (const auto &[address, byte_entry] : impl->memory) {
    auto is_writeable{false};
    auto is_executable{false};
    switch (byte_entry.second) {
      case BytePermission::kUnknown: {
        std::stringstream ss;
        ss << "Unknown byte permissions for byte at address "
           << std::hex << address;
        return JSONEncodeError(ss.str());
      }
      case BytePermission::kReadable:
        break;
      case BytePermission::kReadableWritable:
        is_writeable = true;
        break;
      case BytePermission::kReadableWritableExecutable:
        is_writeable = true;
        is_executable = true;
        break;
      case BytePermission::kReadableExecutable:
        is_executable = true;
        break;
    }

    // Need to introduce a new range.
    if (ranges.empty() || (ranges.back().begin_address + 1u) != address ||
        ranges.back().is_writeable != is_writeable ||
        ranges.back().is_executable != is_executable) {
      Range new_range;
      new_range.begin_address = address;
      new_range.is_writeable = is_writeable;
      new_range.is_executable = is_executable;
      ranges.emplace_back(std::move(new_range));
    }

    char lo_nibble = "012345678abcdef"[(byte_entry.first >> 0u) & 0xFu];
    char hi_nibble = "012345678abcdef"[(byte_entry.first >> 4u) & 0xFu];

    ranges.back().hex_bytes.push_back(hi_nibble);
    ranges.back().hex_bytes.push_back(lo_nibble);
  }

  // Encode the range-based memory implementation to JSON.
  for (Range &range : ranges) {
    llvm::json::Object ro;
    ro.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("address"),
        static_cast<int64_t>(range.begin_address)});

    ro.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("is_writeable"),
        range.is_writeable});

    ro.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("is_executable"),
        range.is_executable});

    ro.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("data"),
        std::move(range.hex_bytes)});

    memory.emplace_back(std::move(ro));
  }

  for (auto [from_address, to_address] : impl->redirections) {
    if (from_address == to_address) {
      std::stringstream ss;
      ss << "Trivial control-flow redirection cycle on address "
         << std::hex << from_address;
      return JSONEncodeError(ss.str());
    }

    llvm::json::Array entry;
    entry.push_back(static_cast<int64_t>(from_address));
    entry.push_back(static_cast<int64_t>(to_address));
    redirects.emplace_back(std::move(entry));
  }

  for (const auto &to_list : impl->targets) {
    if (to_list->target_addresses.empty()) {
      std::stringstream ss;
      ss << "Empty destination address list for source address "
         << std::hex << to_list->address;
      return JSONEncodeError(ss.str());
    }

    llvm::json::Array destinations;
    for (auto dest_address : to_list->target_addresses) {
      destinations.push_back(static_cast<int64_t>(dest_address));
    }

    llvm::json::Object tl;
    tl.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("source"),
        static_cast<int64_t>(to_list->address)});

    tl.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("is_complete"),
        to_list->is_complete});

    tl.insert(llvm::json::Object::KV{
        llvm::json::ObjectKey("destinations"),
        std::move(destinations)});

    targets.emplace_back(std::move(tl));
  }

  llvm::json::Object json;
  llvm::StringRef arch(remill::GetArchName(impl->arch->arch_name));
  llvm::StringRef os(remill::GetOSName(impl->arch->os_name));
  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("arch"), arch});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("os"), os});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("functions"),
      std::move(functions)});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("call_sites"),
      std::move(call_sites)});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("variables"),
      std::move(variables)});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("symbols"),
      std::move(symbols)});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("memory"),
      std::move(memory)});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("control_flow_redirections"),
      std::move(redirects)});

  json.insert(llvm::json::Object::KV{
      llvm::json::ObjectKey("control_flow_targets"),
      std::move(targets)});

  return json;
}

// Return the function beginning at `address`, or an empty `shared_ptr`.
std::shared_ptr<const FunctionDecl> Specification::FunctionAt(
    std::uint64_t address) const {
  auto it = impl->address_to_function.find(address);
  if (it != impl->address_to_function.end()) {
    return std::shared_ptr<const FunctionDecl>(impl, it->second);
  } else {
    return {};
  }
}

// Return the global variable beginning at `address`, or an empty `shared_ptr`.
std::shared_ptr<const VariableDecl> Specification::VariableAt(
    std::uint64_t address) const {
  auto it = impl->address_to_var.find(address);
  if (it != impl->address_to_var.end()) {
    if (it->second->address == address) {
      return std::shared_ptr<const VariableDecl>(impl, it->second);
    }
  }
  return {};
}

// Return the global variable containing `address`, or an empty `shared_ptr`.
std::shared_ptr<const VariableDecl> Specification::VariableContaining(
    std::uint64_t address) const {
  auto it = impl->address_to_var.find(address);
  if (it != impl->address_to_var.end()) {
    return std::shared_ptr<const VariableDecl>(impl, it->second);
  } else {
    return {};
  }
}

// Call `cb` on each symbol in the spec, until `cb` returns `false`.
void Specification::ForEachSymbol(std::function<bool(std::uint64_t,
                                      const std::string &)> cb) const {
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
    std::function<bool(std::shared_ptr<const ControlFlowTargetList>)> cb) const {
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

}  // namespace anvill
