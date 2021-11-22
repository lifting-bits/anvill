/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/ABI.h>

namespace anvill {

const std::string kAnvillNamePrefix("__anvill_");

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the program counter.
const std::string kSymbolicPCName(kAnvillNamePrefix + "pc");

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the stack pointer.
const std::string kSymbolicSPName(kAnvillNamePrefix + "sp");

// The name of the global variable that is used to taint (via constant
// expressions) data that operates on the return address.
const std::string kSymbolicRAName(kAnvillNamePrefix + "ra");

// This is the prefix of the variable name of an "unmodelled" register. When
// we lift, we fill up Remill's `State` structure with loads from "register
// global variables," which exist to signal dependencies on native registers
// without descending into inline assembly or LLVM's `llvm.read_register`
// intrinsic. These register global variables are names as `<prefix><reg_name>`.
const std::string kUnmodelledRegisterPrefix(kAnvillNamePrefix + "reg_");

// This is the prefix of a type hint function/variable name. These hints exist
// to tell anvill that something has a different type. Type hints objects encode
// type information within symbolic functions so the type information can
// survive optimization.
const std::string kTypeHintFunctionPrefix(kAnvillNamePrefix + "type_hint");

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
const std::string kMemoryPointerEscapeFunction(kAnvillNamePrefix +
                                               "memory_escape");

const std::string kStackFrameTypeNameSuffix(".frame_type");

// The prefix string used while naming the global variables at an address
// with type information as suffix.
const std::string kGlobalVariableNamePrefix("var_");

// The prefix string which is used while naming the global aliases from the
// global variables
const std::string kGlobalAliasNamePrefix("data_");

// Prefix used to identify symbolic values for stack frame values
const std::string kSymbolicStackFrameValuePrefix(kAnvillNamePrefix + "stack_");

// The anvill function used to handle complete switch cases
const std::string kAnvillSwitchCompleteFunc(
    kAnvillNamePrefix + "complete_switch");

// The anvill function used to handle incomplete switch cases
const std::string kAnvillSwitchIncompleteFunc(
    kAnvillNamePrefix + "incomplete_switch");

// The name of the uninterpreted function that implements data provenance
// tracking.
extern const std::string kAnvillDataProvenanceFunc(
    kAnvillNamePrefix + "data_provenance");

}  // namespace anvill
