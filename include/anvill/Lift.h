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

#pragma once

#include <remill/BC/Lifter.h>

#include <memory>

namespace llvm {
class Module;
}  // namespace llvm

namespace remill {
class IntrinsicTable;
}  // namespace remill

namespace anvill {

class Program;
struct ValueDecl;

// Manages lifting of machine code functions from the input
// program.
class TraceManager : public remill::TraceManager {
 public:
  virtual ~TraceManager(void);

  static std::unique_ptr<TraceManager> Create(llvm::Module &semantics_module,
                                              const Program &);
};

// Produce one or more instructions in `in_block` to load and return
// the lifted value associated with `decl`.
llvm::Value *LoadLiftedValue(const ValueDecl &decl,
                             const remill::IntrinsicTable &intrinsics,
                             llvm::BasicBlock *in_block, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr);

// Produce one or more instructions in `in_block` to store the
// native value `native_val` into the lifted state associated
// with `decl`.
llvm::Value *StoreNativeValue(llvm::Value *native_val, const ValueDecl &decl,
                              const remill::IntrinsicTable &intrinsics,
                              llvm::BasicBlock *in_block,
                              llvm::Value *state_ptr, llvm::Value *mem_ptr);

}  // namespace anvill
