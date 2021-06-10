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

#include <llvm/IR/Module.h>

#include <functional>
#include <vector>

namespace llvm {
class CallBase;
class Function;
class Instruction;
class PointerType;
class Value;
}  // namespace llvm
namespace anvill {

// Returns `true` if it seems like a basic block is sane.
bool BasicBlockIsSane(llvm::BasicBlock *block);

inline static bool BasicBlockIsSane(llvm::Instruction *inst) {
  return BasicBlockIsSane(inst->getParent());
}

// Find all function calls in `func` such that `pred(call)` returns `true`.
std::vector<llvm::CallBase *>
FindFunctionCalls(llvm::Function &func,
                  std::function<bool(llvm::CallBase *)> pred);

// Convert the constant `val` to have the pointer type `dest_ptr_ty`.
llvm::Value *ConvertToPointer(llvm::Instruction *usage_site,
                              llvm::Value *val_to_convert,
                              llvm::PointerType *dest_ptr_ty);

// Returns the function's IR
std::string GetFunctionIR(llvm::Function &func);

// Returns the module's IR
std::string GetModuleIR(llvm::Module &module);

}  // namespace anvill
