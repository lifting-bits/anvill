/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <optional>
#include <string>
#include <vector>

namespace llvm {
class Function;
class FunctionPass;
class FunctionPassManager;
}  // namespace llvm
namespace anvill {

class CrossReferenceResolver;
class EntityLifter;
class LifterOptions;
class MemoryProvider;
class SliceManager;

// Error severity; `fatal` is used when an error has occurred and
// the LLVM module is no longer in a consistent state
enum class SeverityType {
  Information,
  Warning,
  Error,
  Fatal,
};

// An error, as emitted by an LLVM pass
struct TransformationError final {

  // The name of the pass that emitted the error
  std::string pass_name;

  // A short description of this error, containing everything
  // except the module IR
  std::string description;

  // Error severity
  SeverityType severity;

  // Name of the error code
  std::string error_code;

  // Error message
  std::string message;

  // The name of the module the pass was operating on
  std::string module_name;

  // If the error was emitted by a function pass, this is the
  // name of the function that was being transformed
  std::optional<std::string> function_name;

  // The module IR, before the pass took place
  std::optional<std::string> func_before;

  // The module IR, after the transformation pass has been
  // executed. It will be empty if nothing changed compared
  // to the original module iR
  std::optional<std::string> func_after;
};

// An object that is used to collect errors emitted by LLVM
// passes
class TransformationErrorManager {
 private:
  std::vector<TransformationError> error_list;
  bool has_fatal_error{false};

 public:
  ~TransformationErrorManager(void);

  // Inserts a new error
  inline void Insert(TransformationError error) {
    error_list.emplace_back(std::move(error));
  }

  // Returns true if there is at least one error stored that
  // is marked as fatal (i.e. signalling that the LLVM module
  // is no longer in a good state)
  inline bool HasFatalError(void) const {
    return has_fatal_error;
  }

  // Returns a list of all the stored errors
  inline std::vector<TransformationError> TakeErrorList(void) {
    return std::move(error_list);
  }
};

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
void AddSinkSelectionsIntoBranchTargets(
    llvm::FunctionPassManager &fpm, TransformationErrorManager &error_manager);

// Remill semantics sometimes contain compiler barriers (empty inline assembly
// statements), especially related to floating point code (i.e. preventing
// re-ordering of floating point operations so that we can capture the flags).
// This pass eliminates those empty inline assembly statements.
void AddRemoveCompilerBarriers(llvm::FunctionPassManager &fpm);

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
void AddSplitStackFrameAtReturnAddress(
    llvm::FunctionPassManager &fpm, TransformationErrorManager &error_manager);

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
void AddRemoveUnusedFPClassificationCalls(llvm::FunctionPassManager &fpm);

// Lowers the `__remill_read_memory_NN`, `__remill_write_memory_NN`, and the
// various atomic read-modify-write variants into LLVM loads and stores.
void AddLowerRemillMemoryAccessIntrinsics(llvm::FunctionPassManager &fpm);

// Type information from prior lifting efforts, or from front-end tools
// (e.g. Binary Ninja) is plumbed through the system by way of calls to
// intrinsic functions such as `__anvill_type<blah>`. These function calls
// don't interfere (too much) with optimizations, and they also survive
// optimizations. In general, the key role that they serve is to enable us to
// propagate through pointer type information at an instruction/register
// granularity.
//
// These function calls need to be removed/lowered into `inttoptr` or `bitcast`
// instructions.
void AddLowerTypeHintIntrinsics(llvm::FunctionPassManager &fpm);

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
void AddBrightenPointerOperations(llvm::FunctionPassManager &fpm,
                                  unsigned max_gas = 250);

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
void AddRemoveRemillFunctionReturns(
    llvm::FunctionPassManager &fpm,
    const CrossReferenceResolver &xref_resolver);

// This function pass makes use of the `__anvill_sp` usages to create an
// `llvm::StructType` that acts as a stack frame. This initial stack frame
// is an array of bytes. The initial purpose of this stack frame is to observe
// uses of possibly uninitialized bytes in the stack (via `kSymbolic` in
// `StackFrameStructureInitializationProcedure` in `options`), to enable
// baseline scalar replacement of aggregates (SROA), and if that pass fails
// to eliminate the stack frame, then to enable splitting of the stack from
// into components (see `CreateSplitStackFrameAtReturnAddress`) such that
// SROA can apply to the arguments and return address components.
void AddRecoverStackFrameInformation(llvm::FunctionPassManager &fpm,
                                     TransformationErrorManager &error_manager,
                                     const LifterOptions &options);

// Anvill-lifted code is full of references to constant expressions related
// to `__anvill_pc`. These constant expressions exist to "taint" values as
// being possibly related to the program counter, and thus likely being
// pointers.
//
// This goal of this pass is to opportunistically identify uses of values
// that are related to the program counter, and likely to be references to
// other entitities. We say opportunistic because that pass is not guaranteed
// to replace all such references, and will in fact leave references around
// for later passes to benefit from.
void AddRecoverEntityUseInformation(llvm::FunctionPassManager &fpm,
                                    const CrossReferenceResolver &resolver);

// Some machine code instructions explicitly introduce undefined values /
// behavior. Often, this is a result of the CPUs of different steppings of
// an ISA producing different results for specific registers. For example,
// some instructions leave the value of specific arithmetic flags instructions
// in an undefined state.
//
// Remill models these situations using opaque function calls, i.e. an
// undefined value is produced via a call to something like
// `__remill_undefined_8`, which represents an 8-bit undefined value. We want
// to lower these to `undef` values in LLVM; however, we don't want to do this
// too early, otherwise the "undefinedness" can spread and possibly get out
// of control.
//
// This pass exists to do the lowering to `undef` values, and should be run
// as late as possible.
void AddLowerRemillUndefinedIntrinsics(llvm::FunctionPassManager &fpm);

// This function pass will attempt to fold the following instruction
// combinations:
// {SelectInst, PHINode}/{BinaryOperator, CastInst, GetElementPtrInst}
void AddInstructionFolderPass(llvm::FunctionPassManager &fpm);

// Removes trivial PHI and select nodes. These are PHI and select nodes whose
// incoming values or true/false values match. This can happen as a result of
// the instruction folding pass that hoists and folds values up through selects
// and PHI nodes, followed by the select sinking pass, which pushes values down.
void AddRemoveTrivialPhisAndSelects(llvm::FunctionPassManager &fpm);

// The pass transforms bitcode to replace the calls to `__remill_jump` into
// `__remill_function_return` if a value returned by `llvm.returnaddress`, or
// casted from `__anvill_ra`, reaches to its `PC` argument.
//
// The transform is written to fix the bitcode generated for aarch32 architecture
// where multiple instructions semantic can be used to return from the function
// and they might be categorized as (conditional/unconditional) indirect jumps
//
// It identifies the possible cases where a return instruction is lifted as
// indirect jump and fixes the intrinsics for them.

// NOTE: The pass should be run as late as possible in the list but before
// `RemoveRemillFunctionReturns` transform
void AddTransformRemillJumpIntrinsics(llvm::FunctionPassManager &fpm,
                                      const EntityLifter &lifter);

// Finds values in the form of:
//
//      %cmp = icmp eq val1, val2
//      %n = xor %cmp, 1
//
//      %br %cmp, d1, d2      (optional)
//
// and converts it to:
//
//      %cmp = icmp ne val1, val2
//      %n = %cmp
//      %br %cmp, d2, d1
//
// This happens often enough in lifted code due to bit shift ops, and the code
// with xors is more difficult to analyze and for a human to read. This pass
// should only work on boolean values, and handle when those are used in
// branches and selects.
void AddConvertXorToCmp(llvm::FunctionPassManager &fpm);

// Looks for the following patterns that can be converted into casts, where
// we focus on high-level casting patterns, i.e. truncations, zero-extensions,
// and sign-extensions.
//
//      and i64 %val, 0xff          -> %down_casted_val = trunc %val to i8
//                                     %new_val = zext %down_casted_val to i64
//      and i64 %val, 0xffff        -> %down_casted_val = trunc %val to i16
//                                     %new_val = zext %down_casted_val to i64
//      and i64 %val, 0xffffffff    -> %down_casted_val = trunc %val to i32
//                                     %new_val = zext %down_casted_val to i64
//
// We also look for patterns of the form:
//
//      %low_val = shl i64 %val, 32
//      %signed_val = ashr i64 %low_val, 32
//
// And convert it into:
//
//      %low_val = trunc i64 %val to i32
//      %signed_val = sext i32 %low_val to i64
//
// In general, these types of patterns are easier to lift into a combination
// of one down cast, followed by one implicit upcast in decompiled code, and
// thus look simpler than the shifting/masking variants.
void AddConvertMasksToCasts(llvm::FunctionPassManager &fpm);

// Removes calls to `__remill_delay_slot_begin` and `__remill_delay_slot_end`.
// These calls surround the lifted versions of delayed instructions, to signal
// their location in the bitcode.
void AddRemoveDelaySlotIntrinsics(llvm::FunctionPassManager &fpm);

// Removes calls to `__remill_error`.
void AddRemoveErrorIntrinsics(llvm::FunctionPassManager &fpm);


void AddSwitchLoweringPass(llvm::FunctionPassManager &fpm,
                           const MemoryProvider &memprov,
                           SliceManager &slc);


void AddSimplifyStackArithFlags(llvm::FunctionPassManager &fpm,
                                bool stack_pointer_is_signed);


void AddBranchRecovery(llvm::FunctionPassManager &fpm);

void AddRemoveStackPointerCExprs(llvm::FunctionPassManager &fpm);

void AddRemoveFailedBranchHints(llvm::FunctionPassManager &fpm);

}  // namespace anvill
