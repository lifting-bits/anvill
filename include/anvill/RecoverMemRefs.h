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

namespace llvm {
class Module;
}

namespace anvill {

class Program;
// Attempts to recover references to memory objects. It does this by visiting
// all operands of all instructions in `module` and looking for pointers
// derived from constant integer values that are mapped as addresses in `program`.
void RecoverMemoryReferences(const Program &program, llvm::Module &module);

}  // namespace anvill
