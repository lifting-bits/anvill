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
class Function;
class FunctionPass;
}  // namespace llvm
namespace anvill {

class ConstantCrossReferenceResolver;

// When lifting conditional control-flow, we end up with the following pattern:
//
//        %25 = icmp eq i8 %24, 0
//        %26 = select i1 %25, i64 TAKEN_PC, i64 NOT_TAKEN_PC
//        br i1 %25, label %27, label %34
//
//        27:
//        ... use of %26
//
//        34:
//        ... use of %26
//
// This function pass transforms the above pattern into the following:
//
//        %25 = icmp eq i8 %24, 0
//        br i1 %25, label %27, label %34
//
//        27:
//        ... use of TAKEN_PC
//
//        34:
//        ... use of NOT_TAKEN_PC
//
// When this happens, we're better able to fold cross-references at the targets
// of conditional branches.
llvm::FunctionPass *CreateSinkSelectionsIntoBranchTargets(void);

// Remill semantics sometimes contain compiler barriers (empty inline assembly
// statements), especially related to floating point code (i.e. preventing
// re-ordering of floating point operations so that we can capture the flags).
// This pass eliminates those empty inline assembly statements.
llvm::FunctionPass *CreateRemoveCompilerBarriers(void);

// Analyze `func` and determine if the function stores the return value of
// the `llvm.returnaddress` intrinsic into an `alloca` (presumed to be the
// stack frame). If so, split the stack frame into three separate `alloca`s:
//
//    1) One for every up to but not including the location where the return
//       address is stored.
//    2) One for the return address itself.
//    3) One for everything else.
//
// The `arch` is consulted to determine the default stack growth direction,
// which informs the behavior of the function in the presence of multiple
// stores of the return address into a stack frame.
//
// Anvill's approach to stack frame recovery is slightly atypical: if a
// function's return address is stored on the stack, or if a function's
// arguments are stored on the stack (typical in x86), then these are all
// considered to be part of the stack frame. In that way, the stack frame
// actually extends into what is typically thought of as the caller's stack
// frame. This approach is very convenient, but comes at the cost of having
// to do this particular transformation in order to recover more typical stack
// frame structures.
llvm::FunctionPass *CreateSplitStackFrameAtReturnAddress(void);

// Remove unused calls to floating point classification functions. Calls to
// these functions are present in a bunch of FPU-related instruction semantics
// functions. It's frequently the case that instructions don't actually care
// about the FPU state, though. In these cases, we won't observe the return
// values of these classification functions being used. However, LLVM can't
// eliminate the calls to these functions on its own because they are not
// "pure" functions.
//
// NOTE(pag): This pass must be applied before any kind of renaming of lifted
//            functions is performed, so that we don't accidentally remove
//            calls to classification functions present in the target binary.
llvm::FunctionPass *CreateRemoveUnusedFPClassificationCalls(void);

// Lowers the `__remill_read_memory_NN`, `__remill_write_memory_NN`, and the
// various atomic read-modify-write variants into LLVM loads and stores.
llvm::FunctionPass *CreateLowerRemillMemoryAccessIntrinsics(void);

// Anvill-lifted bitcode operates at a very low level, swapping between integer
// and pointer representations. It is typically for just-lifted bitcode to
// perform integer arithmetic on addresses, then cast those integers into
// pointers in order to do a `load` or `store`. This happens because the bitcode
// we get from Remill uses memory access intrinsics, which abstract over the
// target program's address space and model memory loads/stores in terms of
// intrinsic function calls operating on integer addresses. When these intrinsic
// calls are lowered into `load` and `store` instructions by
// `LowerRemillMemoryAccessIntrinsics`, we are left with a mixed bag in integer
// arithmetic and then `inttoptr` casts.
//
// Ideally, we want to comprehensively brighten all integer operations that
// produce pointers into pointer operations. For example, integer arithmetic
// should instead become `getelementptr` instructions, where possible, which
// model pointer arithmetic at a higher level.
//
// This function attempts to apply a battery of pattern-based transforms to
// brighten integer operations into pointer operations.
llvm::FunctionPass *CreateBrightenPointerOperations(
    const ConstantCrossReferenceResolver &resolver);

// Transforms the bitcode to eliminate calls to `__remill_function_return`,
// where appropriate. This will not succeed for all architectures, but is
// likely to always succeed for x86(-64) and aarch64, due to their support
// for the `llvm.addressofreturnaddress` intrinsic.
//
// When we lift bitcode, we represent the control-flow transfer semantics of
// function returns with calls to `__remill_function_return`. This is another
// three-argument Remill function, where the second argument is the program
// counter. We're particularly interested in observing this program counter
// value, as it can tell us if this function respects normal return conventions
// (i.e. returns to its return address) or not. The way we try to observe this
// is by inspecting the program counter argument, and seeing if it is
// `__anvill_ra` or the (casted) value returned from the `llvm.returnaddress`
// intrinsic.
//
// When we match the expected pattern, we can eliminate calls to
// `__remill_function_return`. If we don't match the pattern, then it suggests
// that it is possible that the function alters its return address, or that
// something is preventing our analysis from deducing that the return address
// reaches the `__remill_function_return` call's program counter argument.
//
// On x86(-64) and AArch64, we can use the `llvm.addressofreturnaddress` to
// update the return address in place when we fail to match the pattern,
// thereby letting us eliminate the call to `__remill_function_return`.
//
// NOTE(pag): This pass should be applied as late as possible, as the call to
//            `__remill_function_return` depends upon the memory pointer.
llvm::FunctionPass *CreateRemoveRemillFunctionReturns(void);

// Transforms the bitcode in `func`, looking for uses of the
// `llvm.returnaddress` intrinsic function. If the return value of this function
// is stored into memory, then we try to identify any loads from the same
// memory region, and forward the stored value to those loads. Note that the
// stores themselves are retained.
//llvm::FunctionPass *CreateForwardReturnAddressStoresToLoads(void);


}  // namespace anvill
