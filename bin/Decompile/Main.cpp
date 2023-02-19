/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Lifters.h>
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <anvill/Utils.h>
#include <anvill/Version.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/ADT/Statistic.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/MemoryBuffer.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>

#include <cstdint>
#include <iomanip>
#include <ios>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>

DEFINE_string(spec, "", "Path to a JSON specification of code to decompile.");
DEFINE_string(ir_out, "", "Path to file where the LLVM IR should be saved.");
DEFINE_string(bc_out, "",
              "Path to file where the LLVM bitcode should be "
              "saved.");
DEFINE_string(stats_out, "", "Path to emit decompilation statistics");

DEFINE_bool(add_breakpoints, false,
            "Add breakpoint_XXXXXXXX functions to the "
            "lifted bitcode.");

DEFINE_bool(add_names, false, "Try to apply symbol names to lifted entities.");
DEFINE_bool(disable_opt, false, "Dont apply optimization passes");
DEFINE_bool(llvm_debug, false, "Enable LLVM debug flag");

DEFINE_string(
    default_callable_spec, "",
    "a default specification for functions for which we dont have a type");

DEFINE_string(
    lift_list, "",
    "a list of function addresses to lift. By default anvill lifts all functions available in the spec");

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

int main(int argc, char *argv[]) {
  // get version string from git, and put as output to --version
  // from gflags
  SetVersion();
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  if (FLAGS_spec.empty()) {
    std::cerr
        << "Please specify a path to a Protobuf specification file in '--spec'"
        << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_spec == "/dev/stdin") {
    FLAGS_spec = "-";
  }

  auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(FLAGS_spec);
  if (remill::IsError(maybe_buff)) {
    std::cerr << "Unable to read Protobuf spec file '" << FLAGS_spec
              << "': " << remill::GetErrorString(maybe_buff) << std::endl;
    return EXIT_FAILURE;
  }

  const std::unique_ptr<llvm::MemoryBuffer> &buff =
      remill::GetReference(maybe_buff);

  llvm::LLVMContext context;
  llvm::Module module("lifted_code", context);

  auto maybe_spec =
      anvill::Specification::DecodeFromPB(context, buff->getBuffer().str());

  if (!maybe_spec.Succeeded()) {
    std::cerr << maybe_spec.TakeError() << std::endl;
    return EXIT_FAILURE;
  }

  anvill::Specification spec = maybe_spec.Value();
  anvill::SpecificationTypeProvider spec_tp(spec);

  std::unique_ptr<anvill::TypeProvider> tp =
      std::make_unique<anvill::ProxyTypeProvider>(spec_tp);
  if (!FLAGS_default_callable_spec.empty()) {
    anvill::TypeDictionary ty_dict(context);
    anvill::TypeTranslator ty_trans(ty_dict, spec.Arch().get());

    auto maybe_buff =
        llvm::MemoryBuffer::getFileOrSTDIN(FLAGS_default_callable_spec);
    if (remill::IsError(maybe_buff)) {
      std::cerr << "Unable to read Protobuf default callable_spec file '"
                << FLAGS_default_callable_spec
                << "': " << remill::GetErrorString(maybe_buff) << std::endl;
      return EXIT_FAILURE;
    }

    const std::unique_ptr<llvm::MemoryBuffer> &buff =
        remill::GetReference(maybe_buff);

    auto maybe_default_callable = anvill::CallableDecl::DecodeFromPB(
        spec.Arch().get(), buff->getBuffer().str());
    if (!maybe_default_callable.Succeeded()) {
      std::cerr << "default callable_spec did not parse as callable decl: "
                << FLAGS_default_callable_spec << " "
                << maybe_default_callable.TakeError() << std::endl;
    }

    remill::ArchName arch_name = spec.Arch().get()->arch_name;
    auto dtp = std::make_unique<anvill::DefaultCallableTypeProvider>(arch_name,
                                                                     spec_tp);
    dtp->SetDefault(arch_name, maybe_default_callable.Value());

    tp = std::move(dtp);
  }

  anvill::SpecificationControlFlowProvider cfp(spec);
  anvill::SpecificationMemoryProvider mp(spec);
  anvill::LifterOptions options(spec.Arch().get(), module, *tp.get(), cfp, mp);

  //  options.state_struct_init_procedure =
  //      anvill::StateStructureInitializationProcedure::kNone;

  // Annotate instructions with `!pc` metadata that (approximately) tells us
  // where they are from.
  options.pc_metadata_name = "pc";

  // Annotate instructions with `!stack_offset` metadata that tells us where,
  // relative to the stack pointer value on entry to a function, the pointer
  // points.
  options.stack_frame_recovery_options.stack_offset_metadata_name =
      "stack_offset";

  anvill::EntityLifter lifter(options);

  std::unordered_map<uint64_t, std::string> names;
  if (FLAGS_add_names) {
    spec.ForEachSymbol(
        [&names, &module](uint64_t addr, const std::string &name) {
          if (llvm::Triple(module.getTargetTriple()).getVendor() ==
                  llvm::Triple::VendorType::Apple &&
              name.find("_", 0) == 0) {
            names.emplace(addr, name.substr(1));
          } else {
            names.emplace(addr, name);
          }


          return true;
        });
  }


  std::unordered_set<uint64_t> target_funcs;
  if (!FLAGS_lift_list.empty()) {
    std::stringstream ss(FLAGS_lift_list);

    for (uint64_t addr; ss >> std::hex >> addr;) {
      target_funcs.insert(addr);
      LOG(INFO) << "Added target" << std::hex << addr;
      if (ss.peek() == ',') {
        ss.ignore();
      }
    }
  }

  spec.ForEachFunction([&lifter, &names, &target_funcs](auto decl) {
    llvm::Function *func;
    if (FLAGS_lift_list.empty() ||
        target_funcs.find(decl->address) != target_funcs.end()) {
      DLOG(INFO) << "attempting to lift: " << std::hex << decl->address;
      func = lifter.LiftEntity(*decl);
      if (!func) {
        LOG(ERROR) << "Failed to lift: " << std::hex << decl->address;
      }
    } else {
      func = lifter.DeclareEntity(*decl);
    }
    if (FLAGS_add_names) {
      if (auto name_it = names.find(decl->address); name_it != names.end()) {
        func->setName(name_it->second);
      }
    }
    return true;
  });

  spec.ForEachVariable([&lifter, &names](auto decl) {
    llvm::Constant *cv = lifter.LiftEntity(*decl);
    if (FLAGS_add_names) {
      if (auto name_it = names.find(decl->address); name_it != names.end()) {
        if (llvm::GlobalValue *gv = llvm::dyn_cast<llvm::GlobalValue>(cv)) {
          gv->setName(name_it->second);
        }
      }
    }
    return true;
  });

  if (!FLAGS_stats_out.empty()) {
    llvm::EnableStatistics();
  }

  if (FLAGS_llvm_debug) {
    llvm::DebugFlag = true;
  }

  if (!FLAGS_disable_opt) {
    anvill::OptimizeModule(lifter, module, spec.GetBlockContexts(), spec);
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
