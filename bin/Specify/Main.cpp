/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Declarations.h>
#include <anvill/JSON.h>
#include <anvill/Type.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <algorithm>
#include <bitset>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#ifdef _WIN32
#  define STDOUT_FILENO 1
#endif

DEFINE_string(bc_in, "",
              "Path to BITcode file containing data to be specified");

DEFINE_string(json_out, "/dev/stderr", "Path to JSON output file");

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  if (FLAGS_bc_in.empty()) {
    std::cerr << "Please specify a path to a BITcode input file in --bc_in"
              << std::endl;
    return EXIT_FAILURE;
  }

  llvm::LLVMContext context;
  auto module = remill::LoadModuleFromFile(&context, FLAGS_bc_in);
  remill::Arch::ArchPtr arch = remill::Arch::GetModuleArch(*module);
  if (!arch) {
    std::cerr << "Could not infer architecture for bitcode module file"
              << std::endl;
    return EXIT_FAILURE;
  }

  auto arch_name = remill::GetArchName(arch->arch_name);
  auto os_name = remill::GetOSName(arch->os_name);

  anvill::TypeDictionary td(context);
  anvill::TypeTranslator tr(td, arch);
  anvill::JSONTranslator jt(tr, arch);

  llvm::json::Object json;
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("arch"), arch_name.data()});
  json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("os"), os_name.data()});

  llvm::json::Array funcs_json;

  for (auto &function : *module) {

    // Skip llvm debug intrinsics
    if (function.getIntrinsicID()) {
      continue;
    }

    auto maybe_func = anvill::FunctionDecl::Create(function, arch);
    if (!maybe_func.Succeeded()) {
      std::cerr << maybe_func.TakeError() << std::endl;
      return EXIT_FAILURE;
    } else {
      auto decl = maybe_func.TakeValue();
      auto func = jt.Encode(decl);
      if (func.Succeeded()) {
        funcs_json.emplace_back(func.TakeValue());
      } else {
        std::cerr << "Error encoding function '" << function.getName().str()
                  << "' to JSON: " << func.TakeError().message;
        return EXIT_FAILURE;
      }
    }
  }

  // Insert functions array into top level JSON
  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("functions"),
                                     std::move(funcs_json)});

  // Print JSON
  std::unique_ptr<llvm::raw_fd_ostream> fos;
  llvm::raw_ostream *os = nullptr;
  if (FLAGS_json_out == "-" || FLAGS_json_out == "/dev/stdout") {
    os = &(llvm::outs());
  } else if (FLAGS_json_out == "/dev/stderr") {
    os = &(llvm::errs());
  } else {
    std::error_code ec;
    fos.reset(new llvm::raw_fd_ostream(
        FLAGS_json_out.data(), ec,
        llvm::sys::fs::CreationDisposition::CD_CreateAlways,
        llvm::sys::fs::FileAccess::FA_Write,
        llvm::sys::fs::OpenFlags::OF_Text));
    os = fos.get();

    if (ec) {
      std::cerr << "Could not open file '" << FLAGS_json_out
                << "' for writing: " << ec.message() << std::endl;
      return EXIT_FAILURE;
    }
  }

  llvm::json::OStream stream(*os, 2);
  stream.value(llvm::json::Value(std::move(json)));

  return EXIT_SUCCESS;
}
