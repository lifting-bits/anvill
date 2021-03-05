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

#include <anvill/Lifters/Options.h>
#include <anvill/Result.h>
#include <llvm/Pass.h>

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
};

// Contains a list of `load` and `store` instructions that reference
// the stack pointer
using StackPointerRegisterUsages = std::vector<llvm::Instruction *>;

// This structure contains the stack size, along with the lower and
// higher bounds of the offsets, and all the `load` and `store` instructions
// that have been analyzed
struct StackFrameAnalysis final {
  // Describes a `store` or `load` instruction that is operating on
  // the stack, along with the SP-relative offset and the operand
  // type
  struct StackOperation final {
    llvm::Instruction *instr{nullptr};
    std::int32_t offset{};
    llvm::Type *type{nullptr};
  };

  // A list of StackOperation objects
  std::vector<StackOperation> stack_operation_list;

  // Lowest SP-relative offset
  std::int32_t lowest_offset{};

  // Highest SP-relative offset
  std::int32_t highest_offset{};

  // Stack frame size
  std::size_t size{};
};

class RecoverStackFrameInformation final : public llvm::FunctionPass,
                                           public BaseFunctionPass {
  // Lifting options
  const LifterOptions &options;

  // Function pass identifier; `&ID` needs to be unique!
  static char ID;

 public:
  // Creates a new RecoverStackFrameInformation object
  static RecoverStackFrameInformation *Create(const LifterOptions &options);

  // Function pass entry point, called by LLVM
  virtual bool runOnFunction(llvm::Function &function) override;

  // Returns the pass name
  virtual llvm::StringRef getPassName(void) const override;

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
                         const StackFrameAnalysis &stack_frame_analysis);

  // Patches the function, replacing the load/store instructions so that
  // they operate on the new stack frame type we generated
  static Result<std::monostate, StackAnalysisErrorCode>
  UpdateFunction(llvm::Function &function,
                 const StackFrameAnalysis &stack_frame_analysis,
                 bool initialize_stack_frame);

  RecoverStackFrameInformation(const LifterOptions &options);
  virtual ~RecoverStackFrameInformation() override = default;
};

}  // namespace anvill
