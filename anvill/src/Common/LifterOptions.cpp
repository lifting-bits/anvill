/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include "LifterOptions.h"
#include "Program/Program.h"

namespace anvill {

struct LifterOptions::PrivateData final {
  PrivateData(llvm::Module &module_) : module(module_) {}

  llvm::Module &module;
  const remill::Arch *arch{nullptr};
  Configuration configuration;
  Program::Ptr program;
  ControlFlowProvider::Ptr ctrl_flow_provider;
};

LifterOptions::~LifterOptions() {}

const ILifterOptions::Configuration &LifterOptions::Config(void) const {
  return d->configuration;
}

const ControlFlowProvider &LifterOptions::GetControlFlowProvider(void) const {
  return *d->ctrl_flow_provider.get();
}

LifterOptions::LifterOptions(const remill::Arch *arch, llvm::Module &module, const std::filesystem::path &spec_file_path, const Configuration &config) : d(new PrivateData(module)) {
  d->arch = arch;
  d->configuration = config;
  d->program = Program::CreateFromSpecFile(arch, module.getContext(), spec_file_path);
  
  auto ctrl_flow_prov_res = ControlFlowProvider::Create(*d->program.get());
  if (!ctrl_flow_prov_res.Succeeded()) {
    throw std::runtime_error("Failed to create the control flow provider");
  }

  d->ctrl_flow_provider = ctrl_flow_prov_res.TakeValue();
}

ILifterOptions::Ptr ILifterOptions::CreateFromSpecFile(const remill::Arch *arch, llvm::Module &module, const std::filesystem::path &spec_file_path, const Configuration &config) {
  return Ptr(new LifterOptions(arch, module, spec_file_path, config));
}

}  // namespace anvill
