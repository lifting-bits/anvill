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
#include <anvill/Optimize.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <anvill/Version.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/Util.h>
#include <llvm/ADT/Statistic.h>

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

  if (!maybe_spec.Succeeded()) {
    std::cerr << maybe_spec.TakeError().message << std::endl;
    return EXIT_FAILURE;
  }

  anvill::Specification spec = maybe_spec.TakeValue();
  anvill::SpecificationTypeProvider tp(spec);
  anvill::SpecificationControlFlowProvider cfp(spec);
  anvill::SpecificationMemoryProvider mp(spec);
  anvill::LifterOptions options(spec.Arch().get(), module, tp, cfp, mp);

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

  spec.ForEachFunction([&lifter] (auto decl) {
    lifter.LiftEntity(*decl);
    return true;
  });

  spec.ForEachVariable([&lifter] (auto decl) {
    lifter.LiftEntity(*decl);
    return true;
  });

  if (!FLAGS_stats_out.empty()) {
    llvm::EnableStatistics();
  }

  anvill::OptimizeModule(lifter, module);

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
