#include <algorithm>
#include <bitset>
#include <iostream>
#include <sstream>
#include <string>

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
#include <llvm/Demangle/Demangle.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <anvill/Decl.h>

DECLARE_string(arch);
DECLARE_string(os);
DEFINE_string(bc_file, "",
              "Path to BITcode file containing data to be specified");

// Returns a tuple consisting of arch, os
std::tuple<std::string, std::string> getPlatformInformation(
    llvm::Module *module) {
  std::string s = module->getTargetTriple();

  // Split the triple
  replace(s.begin(), s.end(), '-', ' ');
  std::stringstream ss(s);
  std::istream_iterator<std::string> begin(ss);
  std::istream_iterator<std::string> end;
  std::vector<std::string> triple(begin, end);

  // Check that we actually got 3 strings
  if (triple.size() != 3) {
    LOG(ERROR) << "Could not extract a valid triple";
    exit(EXIT_FAILURE);
  }

  std::string arch = triple[0];
  std::string os = triple[2];

  // Change the architecture into something that the rest of anvill and remill
  // can understand.
  if (arch.find("x86_64") != std::string::npos) {
    arch = "amd64";
  }

  // Trim the versioning information
  // TODO: cover the other OSes as well
  if (os.find("macos") != std::string::npos) {
    os = "macos";
  }

  return std::make_tuple(arch, os);
}

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  // Allow all log messages for debugging
  FLAGS_stderrthreshold = 0;

  if (FLAGS_bc_file.empty()) {
    LOG(ERROR) << "Please specify a path to a BITcode input file in --bc_file";
    return EXIT_FAILURE;
  }

  // Overwrite the inherited architecture and os flags if they are not
  // already empty.
  if (!FLAGS_arch.empty() || !FLAGS_os.empty()) {
    LOG(INFO) << "Overwriting architecture and os flags";
    FLAGS_arch = "";
    FLAGS_os = "";
  }

  auto context = new llvm::LLVMContext;
  auto module = remill::LoadModuleFromFile(context, FLAGS_bc_file);

  LOG(INFO) << "Module name: " << module->getName().data();

  std::string arch, os;
  std::tie(arch, os) = getPlatformInformation(module);
  LOG(INFO) << arch << " " << os;

  std::cout << "\n\n\n\n\n" << std::endl;

  llvm::json::Object json;
  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("arch"), arch});
  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("os"), os});

  llvm::json::Array funcs_json;

  for (auto &function : *module) {
    // Skip llvm dbg functions for now
    // TODO: find a way to deal with this
    std::string function_name = llvm::demangle(function.getName().data());
    if (function_name.find("llvm.") == 0) continue;

    // if (function_name.find("dummy") != 0) continue;

    funcs_json.push_back(
        anvill::FunctionDecl::Create(function).SerializeToJSON());
  }

  // Insert functions array into top level JSON
  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("functions"),
                                     llvm::json::Value(std::move(funcs_json))});

  // Print JSON
  llvm::raw_fd_ostream S(STDOUT_FILENO, false);
  S << llvm::formatv("{0:4}", llvm::json::Value(std::move(json)));

  return 0;
}