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

#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <anvill/Version.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Util.h>

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

int main(int argc, char *argv[]) {

  // get version string from git, and put as output to --version
  // from gflags
  SetVersion();
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  if (FLAGS_spec.empty()) {
    std::cerr
        << "Please specify a path to a JSON specification file in '--spec'"
        << std::endl;
    return EXIT_FAILURE;
  }

  if (FLAGS_spec == "/dev/stdin") {
    FLAGS_spec = "-";
  }

  auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(FLAGS_spec);
  if (remill::IsError(maybe_buff)) {
    std::cerr << "Unable to read JSON spec file '" << FLAGS_spec
              << "': " << remill::GetErrorString(maybe_buff) << std::endl;
    return EXIT_FAILURE;
  }

  const std::unique_ptr<llvm::MemoryBuffer> &buff =
      remill::GetReference(maybe_buff);
  auto maybe_json = llvm::json::parse(buff->getBuffer());
  if (remill::IsError(maybe_json)) {
    std::cerr << "Unable to parse JSON spec file '" << FLAGS_spec
              << "': " << remill::GetErrorString(maybe_json) << std::endl;
    return EXIT_FAILURE;
  }

  llvm::LLVMContext context;
  llvm::Module module("lifted_code", context);

  auto maybe_spec = anvill::Specification::DecodeFromJSON(
      context, remill::GetReference(maybe_json));

  if (maybe_spec.Failed()) {
    std::cerr << maybe_spec.TakeError().message << std::endl;
    return EXIT_FAILURE;
  }

  anvill::Specification spec = maybe_spec.TakeValue();
  anvill::SpecificationTypeProvider tp(spec);
  anvill::SpecificationControlFlowProvider cfp(spec);
  anvill::SpecificationMemoryProvider mp(spec);
  anvill::LifterOptions options(spec.Arch().get(), module, tp, cfp, mp);
  anvill::EntityLifter lifter(options);

  auto main_func = spec.FunctionAt(0x401f50u);
  if (main_func) {
    lifter.LiftEntity(*main_func);
  }

  int ret = EXIT_SUCCESS;

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

//
//  llvm::LLVMContext context;
//  llvm::Module module("lifted_code", context);
//
//
//
//  arch->PrepareModule(&module);
//
//
//
//  if (FLAGS_add_breakpoints) {
//    options.add_breakpoints = true;
//  }
//
//  if (FLAGS_enable_provenance) {
//    options.pc_metadata_name = "pc";
//    // TODO(pag): Implement better data provenance tracking.
//    // options.track_provenance = true;
//  }
//
//  // NOTE(pag): Unfortunately, we need to load the semantics module first,
//  //            which happens deep inside the `EntityLifter`. Only then does
//  //            Remill properly know about register information, which
//  //            subsequently allows it to parse value decls in specs :-(
//  anvill::EntityLifter lifter(options, memory, types);
//
//  // Parse the spec, which contains as much or as little details about what is
//  // being lifted as the spec generator desired and put it into an
//  // anvill::Specification object, which is effectively a representation of the spec
//  if (!ParseSpec(arch.get(), context, program, spec, module)) {
//    return EXIT_FAILURE;
//  }
//
//  program.ForEachVariable([&](const anvill::GlobalVarDecl *decl) {
//    (void) lifter.LiftEntity(*decl);
//    return true;
//  });
//
//  // Lift functions.
//  program.ForEachFunction([&](const anvill::FunctionDecl *decl) {
//    (void) lifter.LiftEntity(*decl);
//    return true;
//  });
//
//  // Verify the module
//  if (!remill::VerifyModule(&module)) {
//    std::string json_outs;
//#  if LLVM_VERSION_MAJOR >= 12
//    llvm::json::Path::Root path("");
//    auto ret = llvm::json::fromJSON(json, json_outs, path);
//#  else
//    auto ret = llvm::json::fromJSON(json, json_outs);
//#  endif
//    if (ret) {
//      std::cerr << "Couldn't verify module produced from spec:\n"
//                << json_outs << '\n';
//
//    } else {
//      std::cerr << "Couldn't verify module produced from spec:\n"
//                << buff->getBuffer().str() << '\n';
//    }
//    return EXIT_FAILURE;
//  }
//
//  // OLD: Apply optimizations.
//  anvill::OptimizeModule(lifter, memory, arch.get(), program, module, options);
//
//  std::unordered_set<llvm::Constant *> has_name;
//
//  auto is_called = +[](llvm::Function &func) -> bool {
//    for (auto user : func.users()) {
//      if (llvm::isa<llvm::CallBase>(user)) {
//        return true;
//      }
//    }
//    return false;
//  };
//
//  for (auto &func : module) {
//    if (auto maybe_addr = lifter.AddressOfEntity(&func);
//        maybe_addr && func.isDeclaration()) {
//      program.ForEachNameOfAddress(
//          *maybe_addr,
//          [&](const std::string &name, const anvill::FunctionDecl *,
//              const anvill::GlobalVarDecl *) {
//            if (!has_name.count(&func)) {
//              has_name.insert(&func);
//              func.setName(name);
//            }
//            return true;
//          });
//    }
//  }
//
//  for (auto &func : module) {
//    if (auto maybe_addr = lifter.AddressOfEntity(&func);
//        maybe_addr && is_called(func) && !has_name.count(&func)) {
//      program.ForEachNameOfAddress(
//          *maybe_addr,
//          [&](const std::string &name, const anvill::FunctionDecl *,
//              const anvill::GlobalVarDecl *) {
//            if (!has_name.count(&func)) {
//              has_name.insert(&func);
//              func.setName(name);
//            }
//            return true;
//          });
//    }
//  }
//
//  for (auto &func : module) {
//    if (auto maybe_addr = lifter.AddressOfEntity(&func);
//        maybe_addr && !has_name.count(&func)) {
//      program.ForEachNameOfAddress(
//          *maybe_addr,
//          [&](const std::string &name, const anvill::FunctionDecl *,
//              const anvill::GlobalVarDecl *) {
//            if (!has_name.count(&func)) {
//              has_name.insert(&func);
//              func.setName(name);
//            }
//            return true;
//          });
//    }
//  }
//
//  // Clean out any unneeded things from the module prior to output.
//  {
//    std::unique_ptr<llvm::ModulePass> pass(
//        llvm::createStripDeadPrototypesPass());
//    pass->doInitialization(module);
//    pass->runOnModule(module);
//    pass->doFinalization(module);
//  }
//
//  // Clean up by initializing variables.
//  for (auto &var : module.globals()) {
//    if (!var.isDeclaration()) {
//      continue;
//    }
//    const auto name = var.getName();
//    if (name.startswith(anvill::kAnvillNamePrefix)) {
//      var.setInitializer(llvm::Constant::getNullValue(var.getValueType()));
//      var.setLinkage(llvm::GlobalValue::InternalLinkage);
//    }
//  }
//
}
