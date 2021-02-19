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

#include <remill/Arch/Instruction.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>

#include <set>
#include <unordered_map>

namespace llvm {
class BasicBlock;
class Function;
class Module;
class LLVMContext;
class Type;
class Constant;
class FunctionCallee;
class Instruction;
}  // namespace llvm

namespace remill {
class Arch;
struct Register;
}  // namespace remill

namespace anvill {

class Program;
struct FunctionDecl;
struct TypedRegisterDecl;



}  // namespace anvill
