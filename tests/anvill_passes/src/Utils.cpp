/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "Utils.h"

#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>

#include <iostream>

namespace anvill {

bool VerifyModule(llvm::Module *module) {
  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  if (llvm::verifyModule(*module, &error_stream) != 0) {
    auto module_name = module->getName().str();

    std::string error_message =
        "Module verification failed for '" + module_name + "'";

    error_stream.flush();
    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    std::cerr << error_message << std::endl;
    return false;
  }

  return true;
}

std::unique_ptr<llvm::Module> LoadTestData(llvm::LLVMContext &context,
                                           const std::string &data_name) {
  auto data_path = std::string(ANVILL_TEST_DATA_PATH) + "/" + data_name;

  llvm::SMDiagnostic error;
  auto llvm_module = std::unique_ptr<llvm::Module>(
      llvm::parseIRFile(data_path, error, context));

  if (llvm_module == nullptr) {
    throw std::runtime_error(
        "Failed to load the anvill_passes test data named " + data_name + ": " +
        error.getMessage().str());
  }

  std::string error_buffer;
  llvm::raw_string_ostream error_stream(error_buffer);

  auto succeeded = llvm::verifyModule(*llvm_module.get(), &error_stream) == 0;
  error_stream.flush();

  if (!succeeded) {
    std::string error_message =
        "Module verification failed for '" + data_name + "'";

    if (!error_buffer.empty()) {
      error_message += ": " + error_buffer;
    }

    std::cerr << error_message << std::endl;
  }

  return llvm_module;
}


const PlatformList &GetSupportedPlatforms(void) {
  static const PlatformList kSupportedPlatforms = {{"linux", "amd64"}};

  return kSupportedPlatforms;
}

std::unique_ptr<llvm::LLVMContext> CreateContext(void) {
  auto context = std::make_unique<llvm::LLVMContext>();
  context->enableOpaquePointers();
  return context;
}

}  // namespace anvill
