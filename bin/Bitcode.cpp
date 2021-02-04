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

#include <anvill/Decl.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <algorithm>
#include <bitset>
#include <iostream>
#include <sstream>
#include <string>

#ifdef _WIN32
#  define STDOUT_FILENO 1
#endif

#if __has_include(<llvm/Support/JSON.h>)

#  include <llvm/Support/JSON.h>

DECLARE_string(arch);
DECLARE_string(os);
DEFINE_string(bc_file, "",
              "Path to BITcode file containing data to be specified");

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  if (FLAGS_bc_file.empty()) {
    LOG(ERROR) << "Please specify a path to a BITcode input file in --bc_file";
    return EXIT_FAILURE;
  }

  // Overwrite the inherited architecture and os flags if they are not
  // already empty.
  if (!FLAGS_arch.empty() || !FLAGS_os.empty()) {
    FLAGS_arch = "";
    FLAGS_os = "";
  }

  auto context = new llvm::LLVMContext;
  auto module = remill::LoadModuleFromFile(context, FLAGS_bc_file);
  remill::Arch::ArchPtr arch = remill::Arch::GetModuleArch(*module);
  arch->PrepareModule(remill::LoadArchSemantics(arch.get()));

  auto arch_name = remill::GetArchName(arch->arch_name);
  auto os_name = remill::GetOSName(arch->os_name);

  llvm::json::Object json;
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("arch"), arch_name.data()});
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("os"), os_name.data()});

  llvm::json::Array funcs_json;

  const auto &dl = module->getDataLayout();
  for (auto &function : *module) {

    // Skip llvm debug intrinsics
    if (function.getIntrinsicID()) {
      continue;
    }

    auto maybe_func = anvill::FunctionDecl::Create(function, arch);
    if (remill::IsError(maybe_func)) {
      LOG(ERROR) << remill::GetErrorString(maybe_func);
    } else {
      auto &func = remill::GetReference(maybe_func);
      funcs_json.push_back(func.SerializeToJSON(dl));
    }
  }

  // Insert functions array into top level JSON
  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("functions"),
                                     llvm::json::Value(std::move(funcs_json))});

  // Print JSON
  llvm::raw_fd_ostream S(STDOUT_FILENO, false);
  S << llvm::formatv("{0:4}", llvm::json::Value(std::move(json)));

  return EXIT_SUCCESS;
}
#else
int main(int, char *[]) {
  std::cerr << "LLVM JSON API is not available in this version of LLVM\n";
  return EXIT_FAILURE;
}
#endif
