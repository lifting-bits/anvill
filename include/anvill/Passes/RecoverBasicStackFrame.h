/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

#include <vector>

#include <anvill/Result.h>

namespace llvm {
class IntegerType;
}  // namespace llvm
namespace anvill {

class StackFrameRecoveryOptions;

enum class StackAnalysisErrorCode {
  UnknownError,
  UnsupportedInstruction,
  StackPointerResolutionError,
  StackFrameTypeAlreadyExists,
  InternalError,
  InvalidParameter,
  StackInitializationError,
  FunctionTransformationFailed,
  StackFrameTooBig
};

// Describes an instruction that accesses the stack pointer through the
// `__anvill_sp` symbol.
struct StackPointerUse final {
  inline explicit StackPointerUse(llvm::Use *use_, std::uint64_t type_size_,
                                  std::int64_t stack_offset_)
      : use(use_),
        type_size(type_size_),
        stack_offset(stack_offset_) {}

  // An operand inside of a particular instruction, where `use->getUser()`
  // is an `llvm::Instruction`, and `use->get()` is a value related to the
  // stack pointer.
  llvm::Use *const use;

  // Operand size
  const std::uint64_t type_size;

  // Stack offset referenced
  const std::int64_t stack_offset;
};

// Contains a list of `load` and `store` instructions that reference
// the stack pointer
using StackPointerRegisterUsages = std::vector<llvm::Use *>;

// This structure contains the stack size, along with the lower and
// higher bounds of the offsets, and all the instructions that have
// been analyzed
struct StackFrameAnalysis final {

  // A list of uses that reference the stack pointer
  std::vector<StackPointerUse> instruction_uses;

  // Lowest SP-relative offset
  std::int64_t lowest_offset{};

  // Highest SP-relative offset
  std::int64_t highest_offset{};

  // Stack frame size
  std::size_t size{};
};

// This function pass recovers stack information by analyzing the usage
// of the `__anvill_sp` symbol
class RecoverBasicStackFrame final
    : public llvm::PassInfoMixin<RecoverBasicStackFrame> {

  // Lifting options
  const StackFrameRecoveryOptions &options;

 public:

  // Function pass entry point
  llvm::PreservedAnalyses run(llvm::Function &func,
                              llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name(void);

  // Enumerates all the store and load instructions that reference
  // the stack
  static StackPointerRegisterUsages
  EnumerateStackPointerUsages(llvm::Function &function);

  // Analyzes the stack frame, determining the relative boundaries and
  // collecting the instructions that operate on the stack pointer
  static StackFrameAnalysis AnalyzeStackFrame(
      llvm::Function &function, const StackFrameRecoveryOptions &options);

  // Generates a simple, byte-array based, stack frame for the given
  // function
  static llvm::StructType *
  GenerateStackFrameType(const llvm::Function &function,
                         const StackFrameRecoveryOptions &options,
                         const StackFrameAnalysis &stack_frame_analysis,
                         std::size_t padding_bytes);

  // Generates a new symbolic stack value
  static llvm::GlobalVariable *
  GetStackSymbolicByteValue(llvm::Module &module, std::int32_t offset,
                            llvm::IntegerType *type);

  // Patches the function, replacing the load/store instructions so that
  // they operate on the new stack frame type we generated
  static void UpdateFunction(
      llvm::Function &function, const StackFrameRecoveryOptions &options,
      const StackFrameAnalysis &stack_frame_analysis);

  RecoverBasicStackFrame(const StackFrameRecoveryOptions &options);
};

}  // namespace anvill
