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
  // Describes the relative offset of the operation and
  // its type
  struct MemoryInformation final {
    std::int32_t offset{};
    llvm::Type *type{nullptr};
  };

  std::unordered_map<llvm::Instruction *, MemoryInformation> instruction_map;

  std::int32_t lowest_offset{};
  std::int32_t highest_offset{};

  std::size_t size{};
};

class RecoverStackFrameInformation final : public BaseFunctionPass {
 public:
  // Creates a new RecoverStackFrameInformation object
  static RecoverStackFrameInformation *Create(void);

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
                 const StackFrameAnalysis &stack_frame_analysis);

  RecoverStackFrameInformation(void) = default;
  virtual ~RecoverStackFrameInformation() override = default;
};

}  // namespace anvill
