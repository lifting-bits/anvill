/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <iostream>

#include <anvill/Version.h>
#include <anvill/ILifterOptions.h>

#include <remill/BC/Compat/Error.h>
#include <remill/Arch/Arch.h>
#include <remill/OS/OS.h>
#include <remill/Arch/Name.h>

#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/JSON.h>

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_string(spec, "", "Path to a JSON specification of code to decompile.");
DEFINE_string(ir_out, "", "Path to file where the LLVM IR should be saved.");
DEFINE_string(bc_out, "",
              "Path to file where the LLVM bitcode should be "
              "saved.");

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

bool GetPlatformOptionsFromSpecFile(std::string &os_str, std::string &arch_str) {
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
  arch_str = FLAGS_arch;
  if (maybe_arch) {
    arch_str = maybe_arch->str();
  }

  auto maybe_os = spec->getString("os");
  os_str = FLAGS_os;
  if (maybe_os) {
    os_str = maybe_os->str();
  }

  return true;
}

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

  std::string arch_str;
  std::string os_str;
  if (!GetPlatformOptionsFromSpecFile(arch_str, os_str)) {
    return EXIT_FAILURE;
  }

  std::string module_name;
  if (FLAGS_spec == "-") {
    module_name = "stdin";
  } else {
    module_name = std::filesystem::path(FLAGS_spec).filename().string();
  }

  // Get a unique pointer to a remill architecture object. The architecture
  // object knows how to deal with everything for this specific architecture,
  // such as semantics, register,  etc.
  llvm::LLVMContext context;
  llvm::Module module(module_name, context);

  auto arch = remill::Arch::Build(&context, remill::GetOSName(os_str),
                                  remill::GetArchName(arch_str));
  if (!arch) {
    return EXIT_FAILURE;
  }

  anvill::ILifterOptions::Configuration configuration;
  auto lifter_options = anvill::ILifterOptions::CreateFromSpecFile(arch.get(), module, FLAGS_spec, configuration);
  if (!lifter_options) {
    return EXIT_FAILURE;
  }

  return 0;
}
