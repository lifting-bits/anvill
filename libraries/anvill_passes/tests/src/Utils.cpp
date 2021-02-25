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

#include "Utils.h"

#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>

namespace anvill {

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

  return llvm_module;
}

std::unique_ptr<llvm::Module>
RunFunctionPass(llvm::LLVMContext &context, const std::string &test_data_name,
                llvm::FunctionPass *function_pass) {
  auto module = LoadTestData(context, test_data_name);

  llvm::legacy::FunctionPassManager pass_manager(module.get());
  pass_manager.add(function_pass);

  pass_manager.doInitialization();

  for (auto &function : *module.get()) {
    pass_manager.run(function);
  }

  pass_manager.doFinalization();
  return module;
}

std::string GetModuleIR(llvm::Module &module) {
  std::string module_ir;
  llvm::raw_string_ostream output_stream(module_ir);

  module.print(output_stream, nullptr);
  output_stream.flush();

  return module_ir;
}

}  // namespace anvill
