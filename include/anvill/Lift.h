/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <remill/BC/Lifter.h>

namespace llvm {
class Module;
}  // namespace llvm
namespace anvill {

class Program;

// Manages lifting of machine code functions from the input
// program.
class TraceManager : public remill::TraceManager {
 public:
  virtual ~TraceManager(void);

  static std::unique_ptr<TraceManager> Create(
      llvm::Module &semantics_module, const Program &);
};

}  // namespace anvill
