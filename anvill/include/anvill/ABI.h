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

#include <string>

namespace anvill {

// The common prefix for all special values
extern const std::string kAnvillNamePrefix;

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the program counter.
extern const std::string kSymbolicPCName;

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the stack pointer.
extern const std::string kSymbolicSPName;

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the return address.
extern const std::string kSymbolicRAName;

// This is the prefix of the variable name of an "unmodelled" register. When
// we lift, we fill up Remill's `State` structure with loads from "register
// global variables," which exist to signal dependencies on native registers
// without descending into inline assembly or LLVM's `llvm.read_register`
// intrinsic. These register global variables are names as `<prefix><reg_name>`.
extern const std::string kUnmodelledRegisterPrefix;

// This is the prefix of a type hint function/variable name. These hints exist
// to tell anvill that something has a different type. Type hints objects encode
// type information within symbolic functions so the type information can
// survive optimization.
extern const std::string kTypeHintFunctionPrefix;

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
extern const std::string kMemoryPointerEscapeFunction;

// This is the suffix used when naming stack frame types
extern const std::string kStackFrameTypeNameSuffix;

// The prefix string used while naming the global variables at an address
// with type information as suffix.
extern const std::string kGlobalVariableNamePrefix;

// The prefix string which is used while naming the global aliases from the
// global variables
extern const std::string kGlobalAliasNamePrefix;

// Prefix used to identify symbolic values for stack frame values
extern const std::string kSymbolicStackFrameValuePrefix;

// The anvill function used to handle complete switch cases
extern const std::string kAnvillSwitchCompleteFunc;

// The anvill function used to handle incomplete switch cases
extern const std::string kAnvillSwitchIncompleteFunc;

// The name of the uninterpreted function that implements data provenance
// tracking.
extern const std::string kAnvillDataProvenanceFunc;

}  // namespace anvill
