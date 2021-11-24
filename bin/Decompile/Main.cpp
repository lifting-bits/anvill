/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <cstdint>
#include <iomanip>
#include <ios>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>

#include "anvill/Version.h"

// clang-format off
#include <remill/BC/Compat/CTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/ADT/Statistic.h>

// clang-format on

#include <anvill/ABI.h>
#include <anvill/Lifter.h>
#include <anvill/JSON.h>
#include <anvill/Providers.h>
#include <anvill/Providers.h>
#include <anvill/Type.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <anvill/Specification.h>
#include <anvill/Optimize.h>
#include <anvill/Utils.h>

#include "ControlFlowProvider.h"
#include "MemoryProvider.h"
#include "TypeProvider.h"
#include "Program.h"

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_string(spec, "", "Path to a JSON specification of code to decompile.");
DEFINE_string(ir_out, "", "Path to file where the LLVM IR should be saved.");
DEFINE_string(bc_out, "",
              "Path to file where the LLVM bitcode should be "
              "saved.");
DEFINE_string(stats_out, "", "Path to emit decompilation statistics");

DEFINE_bool(add_breakpoints, false,
            "Add breakpoint_XXXXXXXX functions to the "
            "lifted bitcode.");

DEFINE_bool(enable_provenance, false,
            "Enable tracking of provenance in LLVM debug metadata.");

static void SetVersion(void) {
  std::stringstream ss;
  auto vs = anvill::version::GetVersionString();
  if (0 == vs.size()) {
    vs = "unknown";
  }

  ss << vs << "\n";
  if (!anvill::version::HasVersionData()) {
    ss << "No extended version information found!\n";
  } else {
    ss << "Commit Hash: " << anvill::version::GetCommitHash() << "\n";
    ss << "Commit Date: " << anvill::version::GetCommitDate() << "\n";
    ss << "Last commit by: " << anvill::version::GetAuthorName() << " ["
       << anvill::version::GetAuthorEmail() << "]\n";
    ss << "\n";
    if (anvill::version::HasUncommittedChanges()) {
      ss << "Uncommitted changes were present during build.\n";
    } else {
      ss << "All changes were committed prior to building.\n";
    }
  }
  google::SetVersionString(ss.str());
}

namespace decompile {

class JSONParser {
 private:
  const remill::Arch * const arch;

  // Type translator, which can encode/decode types.
  const anvill::TypeTranslator &type_translator;

  // Context associated with the architecture.
  llvm::LLVMContext &context;

  // Parses JSON declarations.
  anvill::JSONTranslator json_translator;

 public:
  JSONParser(Program &program, const remill::Arch *arch_,
             const anvill::TypeTranslator &type_translator_)
      : arch(arch_),
        type_translator(type_translator_),
        context(*(arch->context)),
        json_translator(arch, type_translator) {}
};

// Try to unserialize variable information.
static bool ParseVariable(const remill::Arch *arch, llvm::LLVMContext &context,
                          anvill::Program &program, llvm::json::Object *obj,
                          llvm::Module &module) {

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR) << "Missing global variable address in specification";
    return false;
  }

  auto address = static_cast<uint64_t>(*maybe_ea);

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    LOG(ERROR) << "Missing 'type' field in global variable.";
    return false;
  }

  anvill::TypeTranslator type_specifier(context, arch->DataLayout());
  std::string spec = maybe_type_str->str();
  auto type_spec_res = type_specifier.DecodeFromString(spec);
  if (!type_spec_res.Succeeded()) {
    auto error = type_spec_res.TakeError();

    LOG(ERROR) << error.message << " in spec " << spec;
    return false;
  }

  llvm::Type *type = type_spec_res.TakeValue();

  if (type->isFunctionTy()) {
    auto type_as_func_ty = llvm::dyn_cast<llvm::FunctionType>(type);
    if (type_as_func_ty == nullptr) {
      LOG(ERROR) << "Failed to cast the function type ptr";
      return false;
    }

    if (auto func_decl = program.FindFunction(address); !func_decl) {
      std::stringstream buffer;
      buffer << "function_variable_" << std::hex << address;

      auto dummy_function = llvm::Function::Create(
          type_as_func_ty, llvm::Function::ExternalLinkage,
          buffer.str().c_str(), module);

      auto maybe_decl = anvill::FunctionDecl::Create(*dummy_function, arch);
      dummy_function->eraseFromParent();

      if (remill::IsError(maybe_decl)) {
        LOG(ERROR) << "Unable to create FunctionDecl for variable of type "
                   << remill::LLVMThingToString(type) << " defined at "
                   << std::hex << address;
        return false;
      }

      auto function_decl = std::move(remill::GetReference(maybe_decl));
      function_decl.address = address;

      auto err = program.DeclareFunction(function_decl);
      if (remill::IsError(err)) {
        LOG(ERROR) << remill::GetErrorString(err);
        return false;
      }
    }

    return true;
  }

  if (!type->isSized()) {
    LOG(ERROR) << "The following type is not sized: " << spec;
    return false;
  }

  anvill::GlobalVarDecl decl;
  decl.type = type;
  decl.address = address;

  auto err = program.DeclareVariable(decl);
  if (remill::IsError(err)) {
    LOG(ERROR) << remill::GetErrorString(err);
    return false;
  }

  return true;
}

// Parse a memory range.
static bool ParseRange(anvill::Program &program, llvm::json::Object *obj) {

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR) << "Missing address in memory range specification";
    return false;
  }

  anvill::ByteRange range;
  range.address = static_cast<uint64_t>(*maybe_ea);

  auto perm = obj->getBoolean("is_writeable");
  if (perm) {
    range.is_writeable = *perm;
  }

  perm = obj->getBoolean("is_executable");
  if (perm) {
    range.is_executable = *perm;
  }

  auto maybe_bytes = obj->getString("data");
  if (!maybe_bytes) {
    LOG(ERROR) << "Missing byte string in memory range specification "
               << "at address '" << std::hex << range.address << std::dec
               << '.';
    return false;
  }

  const llvm::StringRef &bytes = *maybe_bytes;
  if (bytes.size() % 2) {
    LOG(ERROR) << "Length of byte string in memory range specification "
               << "at address '" << std::hex << range.address << std::dec
               << "' must have an even number of characters.";
    return false;
  }

  std::vector<uint8_t> decoded_bytes;
  decoded_bytes.reserve(bytes.size() / 2);

  // Parse out the hex-encoded byte sequence.
  for (auto i = 0ul; i < bytes.size(); i += 2) {
    char nibbles[3] = {bytes[i], bytes[i + 1], '\0'};
    char *parsed_to = nullptr;
    auto byte_val = strtol(nibbles, &parsed_to, 16);

    if (parsed_to != &(nibbles[2])) {
      LOG(ERROR) << "Invalid hex byte value '" << nibbles << "' in memory "
                 << "range specification at address '" << std::hex
                 << range.address << std::dec << "'.";
      return false;
    }

    decoded_bytes.push_back(static_cast<uint8_t>(byte_val));
  }

  range.begin = decoded_bytes.data();
  range.end = decoded_bytes.data() + decoded_bytes.size();

  auto err = program.MapRange(range);
  if (remill::IsError(err)) {
    LOG(ERROR) << remill::GetErrorString(err);
    return false;
  }

  return true;
}

static bool ParseControlFlowRedirection(anvill::Program &program,
                                        llvm::json::Array &redirection_list) {

  auto index{0U};

  std::stringstream buffer;

  for (const llvm::json::Value &list_entry : redirection_list) {
    auto address_pair = list_entry.getAsArray();
    if (address_pair == nullptr) {
      LOG(ERROR)
          << "Non-JSON list entry in 'control_flow_redirections' array of spec file '"
          << FLAGS_spec << "'";

      return false;
    }

    if (address_pair->size() != 2U) {
      LOG(ERROR)
          << "Non-integer pair value in the control_flow_redirections entry #"
          << index << " of the the following spec file: '" << FLAGS_spec << "'";

      return false;
    }

    const auto &source_address_obj = address_pair->operator[](0);
    auto opt_source_address = source_address_obj.getAsInteger();
    if (!opt_source_address) {
      LOG(ERROR)
          << "Invalid integer value in source address for the #" << index
          << " of the control_flow_redirections in the following spec file: '"
          << FLAGS_spec << "'";

      return false;
    }

    const auto &dest_address_obj = address_pair->operator[](1);
    auto opt_dest_address = dest_address_obj.getAsInteger();
    if (!opt_dest_address) {
      LOG(ERROR)
          << "Invalid integer value in destination address for the #" << index
          << " of the control_flow_redirections in the following spec file: '"
          << FLAGS_spec << "'";

      return false;
    }

    auto source_address = opt_source_address.getValue();
    auto dest_address = opt_dest_address.getValue();

    buffer << "  " << std::hex << source_address << " -> " << dest_address
           << "\n";

    program.AddControlFlowRedirection(source_address, dest_address);

    ++index;
  }

  auto redirection_output = buffer.str();
  if (!redirection_output.empty()) {
    std::cout << "Control flow redirections:\n" << redirection_output;
  }
  std::cout << "\n";

  return true;
}

static bool ParseControlFlowTargets(anvill::Program &program,
                                    llvm::json::Array &ctrl_flow_target_list) {

  auto index{0U};

  std::stringstream buffer;

  for (const llvm::json::Value &list_entry : ctrl_flow_target_list) {
    auto entry_as_obj = list_entry.getAsObject();
    if (entry_as_obj == nullptr) {
      LOG(ERROR)
          << "Non-object list entry in 'control_flow_targets' array of spec file '"
          << FLAGS_spec << "' at index " << index;

      return false;
    }

    anvill::ControlFlowTargetList ctrl_flow_target_list = {};

    auto maybe_source = entry_as_obj->getInteger("source");
    if (!maybe_source.hasValue()) {
      LOG(ERROR)
          << "Invalid 'source' value in 'control_flow_targets' array of spec file '"
          << FLAGS_spec << "' at index " << index;

      return false;
    }

    ctrl_flow_target_list.source = maybe_source.getValue();

    auto maybe_complete = entry_as_obj->getBoolean("complete");
    if (!maybe_complete.hasValue()) {
      LOG(ERROR)
          << "Invalid 'complete' value in 'control_flow_targets' array of spec file '"
          << FLAGS_spec << "' at index " << index;

      return false;
    }

    ctrl_flow_target_list.complete = maybe_complete.getValue();

    auto destination_list = entry_as_obj->getArray("destination_list");
    if (destination_list == nullptr) {
      LOG(ERROR)
          << "Non-array 'destination_list' node in 'control_flow_targets' array of spec file '"
          << FLAGS_spec << "' at index " << index;

      return false;
    }

    for (const auto &destination_list_entry : *destination_list) {
      auto maybe_destination = destination_list_entry.getAsInteger();
      if (!maybe_destination.hasValue()) {
        LOG(ERROR)
            << "Non-integer 'destination_list' entry value in 'control_flow_targets' array of spec file '"
            << FLAGS_spec << "' at index " << index;

        return false;
      }

      auto destination = maybe_destination.getValue();
      ctrl_flow_target_list.destination_list.push_back(destination);
    }

    std::sort(ctrl_flow_target_list.destination_list.begin(),
              ctrl_flow_target_list.destination_list.end());

    auto erase_it = std::unique(ctrl_flow_target_list.destination_list.begin(),
                                ctrl_flow_target_list.destination_list.end());

    ctrl_flow_target_list.destination_list.erase(
        erase_it, ctrl_flow_target_list.destination_list.end());

    buffer << "  " << std::hex << ctrl_flow_target_list.source << " -> [ ";

    for (auto dest_it = ctrl_flow_target_list.destination_list.begin();
         dest_it != ctrl_flow_target_list.destination_list.end(); ++dest_it) {

      buffer << (*dest_it);
      if (std::next(dest_it, 1) !=
          ctrl_flow_target_list.destination_list.end()) {
        buffer << ", ";
      }
    }

    buffer << " ] ("
           << (ctrl_flow_target_list.complete ? "complete" : "incomplete")
           << ")\n";

    if (!program.TrySetControlFlowTargets(ctrl_flow_target_list)) {
      LOG(ERROR)
          << "The 'control_flow_targets' entry in the array of spec file '"
          << FLAGS_spec << "' contains duplicates";

      return false;
    }

    ++index;
  }

  auto redirection_output = buffer.str();
  if (!redirection_output.empty()) {
    std::cout << "Control flow targets:\n" << redirection_output;
  }
  std::cout << "\n";

  return true;
}

// Parse the core data out of a JSON specification, and do a small
// amount of validation. A JSON spec contains the following:
//
//  - For each function:
//    - Function name (if any)
//    - Address.
//    - For each argument:
//    - - Argument name
//    - - Location specifier, which is a register name or a stack pointer displacement.
//    - - Type.
//    - For each return value
//    - - Location specifier
//    - - Type.
//
//  - For each global variable:
//    - Variable name (if any)
//    - Type.
//    - Address.
//
//  - For each memory range:
//    - Starting address. No alignment restrictions apply.
//    - Permissions (is_readable, is_writeable, is_executable).
//    - Data (hex-encoded byte string).
static bool ParseSpec(const remill::Arch *arch, llvm::LLVMContext &context,
                      anvill::Program &program, llvm::json::Object *spec,
                      llvm::Module &module) {



//  auto err = program.DeclareFunction(decl);
//  if (remill::IsError(err)) {
//    LOG(ERROR) << remill::GetErrorString(err);
//    return false;
//  }

  auto num_funcs = 0;
  if (auto funcs = spec->getArray("functions")) {
    for (llvm::json::Value &func : *funcs) {
      if (auto func_obj = func.getAsObject()) {
        if (!ParseFunction(arch, context, program, func_obj, module)) {
          return false;
        } else {
          ++num_funcs;
        }
      } else {
        LOG(ERROR) << "Non-JSON object in 'functions' array of spec file '"
                   << FLAGS_spec << "'";
        return false;
      }
    }
  } else if (spec->find("functions") != spec->end()) {
    LOG(ERROR) << "Non-JSON array value for 'functions' in spec file '"
               << FLAGS_spec << "'";
    return false;
  }

  if (auto redirection_list = spec->getArray("control_flow_redirections")) {
    if (!ParseControlFlowRedirection(program, *redirection_list)) {
      LOG(ERROR)
          << "Failed to parse the 'control_flow_redirections' section in spec file '"
          << FLAGS_spec << "'";

      return false;
    }

  } else if (spec->find("control_flow_redirections") != spec->end()) {
    LOG(ERROR)
        << "Non-JSON array value for 'control_flow_redirections' in spec file '"
        << FLAGS_spec << "'";
    return false;
  }

  if (auto ctrl_flow_targets = spec->getArray("control_flow_targets")) {
    if (!ParseControlFlowTargets(program, *ctrl_flow_targets)) {
      LOG(ERROR)
          << "Failed to parse the 'control_flow_targets' section in spec file '"
          << FLAGS_spec << "'";

      return false;
    }

  } else if (spec->find("control_flow_targets") != spec->end()) {
    LOG(ERROR)
        << "Non-JSON array value for 'control_flow_targets' in spec file '"
        << FLAGS_spec << "'";
    return false;
  }

  if (auto vars = spec->getArray("variables")) {
    for (llvm::json::Value &var : *vars) {
      if (auto var_obj = var.getAsObject()) {
        if (!ParseVariable(arch, context, program, var_obj, module)) {
          return false;
        }
      } else {
        LOG(ERROR) << "Non-JSON object in 'variables' array of spec file '"
                   << FLAGS_spec << "'";
        return false;
      }
    }
  } else if (spec->find("variables") != spec->end()) {
    LOG(ERROR) << "Non-JSON array value for 'variables' in spec file '"
               << FLAGS_spec << "'";
    return false;
  }

  if (auto ranges = spec->getArray("memory")) {
    for (llvm::json::Value &range : *ranges) {
      if (auto range_obj = range.getAsObject()) {
        if (!ParseRange(program, range_obj)) {
          return false;
        }
      } else {
        LOG(ERROR) << "Non-JSON object in 'bytes' array of spec file '"
                   << FLAGS_spec << "'";
        return false;
      }
    }
  } else if (spec->find("memory") != spec->end()) {
    LOG(ERROR) << "Non-JSON array value for 'memory' in spec file '"
               << FLAGS_spec << "'";
    return false;
  }

  if (auto symbols = spec->getArray("symbols")) {
    for (llvm::json::Value &maybe_ea_name : *symbols) {
      if (auto ea_name = maybe_ea_name.getAsArray(); ea_name) {
        if (ea_name->size() != 2) {
          LOG(ERROR) << "Symbol entry doesn't have two values in spec file '"
                     << FLAGS_spec << "'";
          return false;
        }
        auto &maybe_ea = ea_name->operator[](0);
        auto &maybe_name = ea_name->operator[](1);

        if (auto ea = maybe_ea.getAsInteger(); ea) {
          if (auto name = maybe_name.getAsString(); name) {
            program.AddNameToAddress(name->str(),
                                     static_cast<uint64_t>(ea.getValue()));
          } else {
            LOG(ERROR)
                << "Second value in symbol entry must be a string in spec file '"
                << FLAGS_spec << "'";
            return false;
          }
        } else {
          LOG(ERROR)
              << "First value in symbol entry must be an integer in spec file '"
              << FLAGS_spec << "'";
          return false;
        }
      } else {
        LOG(ERROR)
            << "Expected array entries inside of 'symbols' array in spec file '"
            << FLAGS_spec << "'";
        return false;
      }
    }
  } else if (spec->find("symbols") != spec->end()) {
    LOG(ERROR) << "Non-JSON array value for 'symbols' in spec file '"
               << FLAGS_spec << "'";
    return false;
  }

  return true;
}

}  // namespace decompile

int main(int argc, char *argv[]) {

  // get version string from git, and put as output to --version
  // from gflags
  SetVersion();
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  if (FLAGS_spec.empty()) {
    LOG(ERROR)
        << "Please specify a path to a JSON specification file in --spec.";
    return EXIT_FAILURE;
  }

  if (FLAGS_spec == "/dev/stdin") {
    FLAGS_spec = "-";
  }

  auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(FLAGS_spec);
  if (remill::IsError(maybe_buff)) {
    LOG(ERROR) << "Unable to read JSON spec file '" << FLAGS_spec
               << "': " << remill::GetErrorString(maybe_buff);
    return EXIT_FAILURE;
  }

  const std::unique_ptr<llvm::MemoryBuffer> &buff =
      remill::GetReference(maybe_buff);
  auto maybe_json = llvm::json::parse(buff->getBuffer());
  if (remill::IsError(maybe_json)) {
    LOG(ERROR) << "Unable to parse JSON spec file '" << FLAGS_spec
               << "': " << remill::GetErrorString(maybe_json);
    return EXIT_FAILURE;
  }

  llvm::json::Value &json = remill::GetReference(maybe_json);
  const auto spec = json.getAsObject();
  if (!spec) {
    LOG(ERROR) << "JSON spec file '" << FLAGS_spec
               << "' must contain a single object.";
    return EXIT_FAILURE;
  }

  // Take the architecture and OS names out of the JSON spec, and
  // fall back on the command-line flags if those are missing.
  auto maybe_arch = spec->getString("arch");
  auto arch_str = FLAGS_arch;
  if (maybe_arch) {
    arch_str = maybe_arch->str();
  }

  auto maybe_os = spec->getString("os");
  auto os_str = FLAGS_os;
  if (maybe_os) {
    os_str = maybe_os->str();
  }

  llvm::LLVMContext context;
  llvm::Module module("lifted_code", context);

  // Get a unique pointer to a remill architecture object. The architecture
  // object knows how to deal with everything for this specific architecture,
  // such as semantics, register,  etc.
  auto arch = remill::Arch::Build(&context, remill::GetOSName(os_str),
                                  remill::GetArchName(arch_str));
  if (!arch) {
    return EXIT_FAILURE;
  }

  arch->PrepareModule(&module);

  anvill::TypeDictionary td(context);
  anvill::TypeTranslator tt(td, arch);

  decompile::Program program;
  decompile::ProgramMemoryProvider mp(program);
  decompile::ProgramControlFlowProvider cfp(program);
  decompile::ProgramTypeProvider tp(program, tt);

  anvill::LifterOptions options(arch.get(), module, tp, cfp, mp);

  if (FLAGS_add_breakpoints) {
    options.add_breakpoints = true;
  }

  if (FLAGS_enable_provenance) {
    options.pc_metadata_name = "pc";
    // TODO(pag): Implement better data provenance tracking.
    // options.track_provenance = true;
  }

  // NOTE(pag): Unfortunately, we need to load the semantics module first,
  //            which happens deep inside the `EntityLifter`. Only then does
  //            Remill properly know about register information, which
  //            subsequently allows it to parse value decls in specs :-(
  anvill::EntityLifter lifter(options, memory, types);

  // Parse the spec, which contains as much or as little details about what is
  // being lifted as the spec generator desired and put it into an
  // anvill::Program object, which is effectively a representation of the spec
  if (!ParseSpec(arch.get(), context, program, spec, module)) {
    return EXIT_FAILURE;
  }

  program.ForEachVariable([&](const anvill::GlobalVarDecl *decl) {
    (void) lifter.LiftEntity(*decl);
    return true;
  });

  // Lift functions.
  program.ForEachFunction([&](const anvill::FunctionDecl *decl) {
    (void) lifter.LiftEntity(*decl);
    return true;
  });

  // Verify the module
  if (!remill::VerifyModule(&module)) {
    std::string json_outs;
#if LLVM_VERSION_MAJOR >= 12
    llvm::json::Path::Root path("");
    auto ret = llvm::json::fromJSON(json, json_outs, path);
#else
    auto ret = llvm::json::fromJSON(json, json_outs);
#endif
    if (ret) {
      std::cerr << "Couldn't verify module produced from spec:\n"
                << json_outs << '\n';

    } else {
      std::cerr << "Couldn't verify module produced from spec:\n"
                << buff->getBuffer().str() << '\n';
    }
    return EXIT_FAILURE;
  }

  if (!FLAGS_stats_out.empty()) {
    llvm::EnableStatistics();
  }
  // OLD: Apply optimizations.
  anvill::OptimizeModule(lifter, memory, arch.get(), program, module, options);

  std::unordered_set<llvm::Constant *> has_name;

  auto is_called = +[](llvm::Function &func) -> bool {
    for (auto user : func.users()) {
      if (llvm::isa<llvm::CallBase>(user)) {
        return true;
      }
    }
    return false;
  };

  for (auto &func : module) {
    if (auto maybe_addr = lifter.AddressOfEntity(&func);
        maybe_addr && func.isDeclaration()) {
      program.ForEachNameOfAddress(
          *maybe_addr,
          [&](const std::string &name, const anvill::FunctionDecl *,
              const anvill::GlobalVarDecl *) {
            if (!has_name.count(&func)) {
              has_name.insert(&func);
              func.setName(name);
            }
            return true;
          });
    }
  }

  for (auto &func : module) {
    if (auto maybe_addr = lifter.AddressOfEntity(&func);
        maybe_addr && is_called(func) && !has_name.count(&func)) {
      program.ForEachNameOfAddress(
          *maybe_addr,
          [&](const std::string &name, const anvill::FunctionDecl *,
              const anvill::GlobalVarDecl *) {
            if (!has_name.count(&func)) {
              has_name.insert(&func);
              func.setName(name);
            }
            return true;
          });
    }
  }

  for (auto &func : module) {
    if (auto maybe_addr = lifter.AddressOfEntity(&func);
        maybe_addr && !has_name.count(&func)) {
      program.ForEachNameOfAddress(
          *maybe_addr,
          [&](const std::string &name, const anvill::FunctionDecl *,
              const anvill::GlobalVarDecl *) {
            if (!has_name.count(&func)) {
              has_name.insert(&func);
              func.setName(name);
            }
            return true;
          });
    }
  }

  // Clean out any unneeded things from the module prior to output.
  {
    std::unique_ptr<llvm::ModulePass> pass(
        llvm::createStripDeadPrototypesPass());
    pass->doInitialization(module);
    pass->runOnModule(module);
    pass->doFinalization(module);
  }

  // Clean up by initializing variables.
  for (auto &var : module.globals()) {
    if (!var.isDeclaration()) {
      continue;
    }
    const auto name = var.getName();
    if (name.startswith(anvill::kAnvillNamePrefix)) {
      var.setInitializer(llvm::Constant::getNullValue(var.getValueType()));
      var.setLinkage(llvm::GlobalValue::InternalLinkage);
    }
  }

  int ret = EXIT_SUCCESS;


  if (!FLAGS_stats_out.empty()) {
    std::error_code ec;
    llvm::raw_fd_ostream stats_out_file(FLAGS_stats_out, ec);
    if (ec) {
      std::cerr << "Could not open stats output file " << FLAGS_stats_out
                << std::endl;
      ret = EXIT_FAILURE;
    } else {
      llvm::PrintStatisticsJSON(stats_out_file);
    }
  }

  if (!FLAGS_ir_out.empty()) {
    if (!remill::StoreModuleIRToFile(&module, FLAGS_ir_out, true)) {
      std::cerr << "Could not save LLVM IR to " << FLAGS_ir_out << '\n';
      ret = EXIT_FAILURE;
    }
  }
  if (!FLAGS_bc_out.empty()) {
    if (!remill::StoreModuleToFile(&module, FLAGS_bc_out, true)) {
      std::cerr << "Could not save LLVM bitcode to " << FLAGS_bc_out << '\n';
      ret = EXIT_FAILURE;
    }
  }

  return ret;
}
