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

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace anvill {

enum class SeverityType {
  Information,
  Warning,
  Error,
  Fatal,
};

struct TransformationError final {
  std::string pass_name;
  std::string description;

  SeverityType severity;
  std::string error_code;
  std::string message;

  std::string module_name;
  std::optional<std::string> function_name;

  std::optional<std::string> module_before;
  std::optional<std::string> module_after;
};

class ITransformationErrorManager {
 public:
  using Ptr = std::unique_ptr<ITransformationErrorManager>;
  static Ptr Create(void);

  ITransformationErrorManager(void) = default;
  virtual ~ITransformationErrorManager(void) = default;

  virtual void Reset(void) = 0;
  virtual void Insert(const TransformationError &error) = 0;

  virtual bool HasFatalError(void) const = 0;
  virtual const std::vector<TransformationError> &ErrorList(void) const = 0;
};

}  // namespace anvill
