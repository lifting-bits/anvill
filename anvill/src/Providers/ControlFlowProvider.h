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

#include <anvill/Providers/IControlFlowProvider.h>

namespace anvill {

class ControlFlowProvider final : public IControlFlowProvider {
 public:
  virtual ~ControlFlowProvider(void) override;

  virtual std::uint64_t GetRedirection(std::uint64_t address) const override;

  virtual std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(std::uint64_t address) const override;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ControlFlowProvider(const Program &program);

  friend class IControlFlowProvider;
};

}  // namespace anvill
