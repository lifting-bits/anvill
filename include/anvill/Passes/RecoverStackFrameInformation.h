/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/LifterOptions.h>

#include <unordered_map>

#include "BaseFunctionPass.h"

namespace anvill {

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
class RecoverStackFrameInformation final
    : public BaseFunctionPass<RecoverStackFrameInformation> {

  // Lifting options
  const LifterOptions &options;

 public:
  // Creates a new RecoverStackFrameInformation object
  static RecoverStackFrameInformation *
  Create(ITransformationErrorManager &error_manager,
         const LifterOptions &options);

  // Function pass entry point
  bool Run(llvm::Function &function, llvm::FunctionAnalysisManager &fam);

  // Returns the pass name
  static llvm::StringRef name();

  // Enumerates all the store and load instructions that reference
  // the stack
  static Result<StackPointerRegisterUsages, StackAnalysisErrorCode>
  EnumerateStackPointerUsages(llvm::Function &function);

  // Analyzes the stack frame, determining the relative boundaries and
  // collecting the instructions that operate on the stack pointer
  static Result<StackFrameAnalysis, StackAnalysisErrorCode>
  AnalyzeStackFrame(llvm::Function &function);

  // Generates a simple, byte-array based, stack frame for the given
  // function
  static Result<llvm::StructType *, StackAnalysisErrorCode>
  GenerateStackFrameType(const llvm::Function &function,
                         const LifterOptions &options,
                         const StackFrameAnalysis &stack_frame_analysis,
                         std::size_t padding_bytes);

  // Generates a new symbolic stack value
  static Result<llvm::GlobalVariable *, StackAnalysisErrorCode>
  GetStackSymbolicByteValue(llvm::Module &module, std::int32_t offset);

  // Patches the function, replacing the load/store instructions so that
  // they operate on the new stack frame type we generated
  static Result<std::monostate, StackAnalysisErrorCode>
  UpdateFunction(llvm::Function &function, const LifterOptions &options,
                 const StackFrameAnalysis &stack_frame_analysis);

  RecoverStackFrameInformation(ITransformationErrorManager &error_manager,
                               const LifterOptions &options);

  virtual ~RecoverStackFrameInformation(void) override = default;
};

}  // namespace anvill
