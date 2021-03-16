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

#include <anvill/ABI.h>

namespace anvill {

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the program counter.
const std::string kSymbolicPCName("__anvill_pc");

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the stack pointer.
const std::string kSymbolicSPName("__anvill_sp");

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the return address.
const std::string kSymbolicRAName("__anvill_ra");

// This is the prefix of the variable name of an "unmodelled" register. When
// we lift, we fill up Remill's `State` structure with loads from "register
// global variables," which exist to signal dependencies on native registers
// without descending into inline assembly or LLVM's `llvm.read_register`
// intrinsic. These register global variables are names as `<prefix><reg_name>`.
const std::string kUnmodelledRegisterPrefix("__anvill_reg_");

// This is the prefix of a type hint function/variable name. These hints exist
// to tell anvill that something has a different type. Type hints objects encode
// type information within symbolic functions so the type information can
// survive optimization.
const std::string kTypeHintFunctionPrefix("__anvill_type_hint");

// This is the name of the "escape hatch" function for the Remill `Memory *`
// value that is taken as an argument to Remill-lifted functions, passed
// around between memory access intrinsics, and then returned from Remill-
// lifted functions. The Remill memory intrinsics are all marked as pure
// functions, essentially permitting LLVM's optimizer to treat them as
// uninterpreted functions. This has the benefit of LLVM optimizations being
// able to optimize "around" and "across" the intrinsic calls, but it also
// means that if we don't have a final use of the memory pointer that LLVM
// is not allowed to optimize then LLVM's optimizations may decide to eliminate
// uses of memory access intrinsics whose (memory pointer) return vales
// appear to be unused.
const std::string kMemoryPointerEscapeFunction("__anvill_memory_escape");

const std::string kStackFrameTypeNameSuffix(".frame_type");

// The prefix string used while naming the global variables at an address
// with type information as suffix.
const std::string kGlobalVariableNamePrefix("var_");

// The prefix string which is used while naming the global aliases from the
// global variables
const std::string kGlobalAliasNamePrefix("data_");

}  // namespace anvill
