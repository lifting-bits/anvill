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

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>
#include <remill/Arch/Name.h>

#include <anvill/Decl.h>

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
  auto arch = remill::Arch::GetModuleArch(*module);
  std::string arch_name = remill::GetArchName(arch->arch_name);
  std::string os_name = remill::GetOSName(arch->os_name);

  // Need arch_module to get the register table for the architecture
  auto arch_module = remill::LoadArchSemantics(arch);
  arch->PrepareModule(arch_module);

  llvm::json::Object json;
  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("arch"), arch_name});
  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("os"), os_name});

  llvm::json::Array funcs_json;

  for (auto &function : *module) {
    // Skip llvm debug intrinsics
    const llvm::StringRef func_name = function.getName();
    if (func_name.startswith("llvm.")) {
      continue;
    }

    funcs_json.push_back(
        anvill::FunctionDecl::Create(function, *module).SerializeToJSON());
  }

  // Insert functions array into top level JSON
  json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("functions"),
                                     llvm::json::Value(std::move(funcs_json))});

  // Print JSON
  llvm::raw_fd_ostream S(STDOUT_FILENO, false);
  S << llvm::formatv("{0:4}", llvm::json::Value(std::move(json)));

  return 0;
}