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

#include <string>

namespace llvm {

class BasicBlock;
class Instruction;
class Value;

}  // namespace llvm
namespace anvill {

// Creates a `sub_<address>` name from an address
std::string CreateFunctionName(uint64_t addr);

// Creates a `data_<address>` name from an address
std::string CreateVariableName(uint64_t addr);

// Looks for any constant expressions in the operands of `inst` and unfolds
// them into other instructions in the same block.
void UnfoldConstantExpressions(llvm::Instruction *inst);

// Copies metadata from the source to destination if both values are instructions.
void CopyMetadataTo(llvm::Value *src, llvm::Value *dst);

}  // namespace anvill
