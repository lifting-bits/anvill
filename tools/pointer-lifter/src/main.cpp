#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>

#include <fstream>
#include <iostream>

#include "anvill/PointerLifter.h"

DEFINE_string(input, "", "Path to INPUT IR file");
DEFINE_string(output, "", "Path to OUTPUT IR file");

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  llvm::LLVMContext context;
  llvm::SMDiagnostic error;
  if (FLAGS_input.empty()) {
    LOG(ERROR) << "Please specify a path to a input IR file with --input.";
    return EXIT_FAILURE;
  }
  if (FLAGS_output.empty()) {
    LOG(ERROR) << "Please specify a path to an output IR file with --output";
    return EXIT_FAILURE;
  }
  LOG(WARNING) << "Input file: " << FLAGS_input << std::endl;
  LOG(WARNING) << "Output file: " << FLAGS_output << std::endl;
  std::string file = std::string(FLAGS_input);
  auto mod = llvm::parseIRFile(file, error, context);
  if (!mod) {
    LOG(ERROR) << "Error! Could not get module\n";
    return EXIT_FAILURE;
  }

  anvill::PointerLifter pointer_lifter(*mod);
  for (auto &func : *mod) {
    if (func.hasName() && func.getName() == "main") {
      LOG(WARNING) << "Lifting main!\n";
      pointer_lifter.LiftFunction(&func);
    }
  }
  mod->print(llvm::errs(), nullptr);
  return 0;
}
