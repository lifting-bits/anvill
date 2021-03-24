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

#include <anvill/ITransformationErrorManager.h>

namespace anvill {

class TransformationErrorManager final : public ITransformationErrorManager {
  std::vector<TransformationError> error_list;
  bool has_fatal_error{false};

 public:
  TransformationErrorManager() = default;
  virtual ~TransformationErrorManager() override = default;

  virtual void Insert(const TransformationError &error) override;
  virtual void Reset(void) override;

  virtual bool HasFatalError(void) const override;

  virtual const std::vector<TransformationError> &
  ErrorList(void) const override;
};

}  // namespace anvill
