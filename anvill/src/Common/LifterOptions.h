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

#pragma once

#include <anvill/ILifterOptions.h>

#include "Providers/ControlFlowProvider.h"

namespace anvill {

// Options that direct the behavior of the code and data lifters.
class LifterOptions final : public ILifterOptions {
 public:
  virtual ~LifterOptions(void) override;

  virtual const Configuration &Config(void) const override;

  const ControlFlowProvider &GetControlFlowProvider(void ) const;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  LifterOptions(const remill::Arch *arch, llvm::Module &module, const std::filesystem::path &spec_file_path, const Configuration &config);
  
  friend class ILifterOptions;
};

}  // namespace anvill
