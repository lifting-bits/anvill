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

// Error severity; `fatal` is used when an error has occurred and
// the LLVM module is no longer in a consistent state
enum class SeverityType {
  Information,
  Warning,
  Error,
  Fatal,
};

// An error, as emitted by an LLVM pass
struct TransformationError final {
  // The name of the pass that emitted the error
  std::string pass_name;

  // A short description of this error, containing everything
  // except the module IR
  std::string description;

  // Error severity
  SeverityType severity;

  // Name of the error code
  std::string error_code;

  // Error message
  std::string message;

  // The name of the module the pass was operating on
  std::string module_name;

  // If the error was emitted by a function pass, this is the
  // name of the function that was being transformed
  std::optional<std::string> function_name;

  // The module IR, before the pass took place
  std::optional<std::string> module_before;

  // The module IR, after the transformation pass has been
  // executed. It will be empty if nothing changed compared
  // to the original module iR
  std::optional<std::string> module_after;
};

// An object that is used to collect errors emitted by LLVM
// passes
class ITransformationErrorManager {
 public:
  using Ptr = std::unique_ptr<ITransformationErrorManager>;
  static Ptr Create(void);

  ITransformationErrorManager(void) = default;
  virtual ~ITransformationErrorManager(void) = default;

  // Deletes all the error that have been accumulated
  virtual void Reset(void) = 0;

  // Inserts a new error
  virtual void Insert(const TransformationError &error) = 0;

  // Returns true if there is at least one error stored that
  // is marked as fatal (i.e. signalling that the LLVM module
  // is no longer in a good state)
  virtual bool HasFatalError(void) const = 0;

  // Returns a list of all the stored errors
  virtual const std::vector<TransformationError> &ErrorList(void) const = 0;
};

}  // namespace anvill
