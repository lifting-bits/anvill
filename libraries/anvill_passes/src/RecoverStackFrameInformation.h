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
  StackInitializationError,
  FunctionTransformationFailed,
};

// Contains a list of `load` and `store` instructions that reference
// the stack pointer
using StackPointerRegisterUsages = std::vector<llvm::Instruction *>;

// This structure contains the stack size, along with the lower and
// higher bounds of the offsets, and all the instructions that have
// been analyzed
struct StackFrameAnalysis final {
  // Describes an instruction that accesses the stack pointer
  // through the __anvill_sp symbol
  struct Instruction final {
    // Detailed information about each operand accessing the
    // stack frame pointer
    struct Operand final {
      // Index of this operand in the parent instruction
      std::size_t index{};

      // Pointer to the llvm Operand
      llvm::Value *obj{nullptr};

      // Operand size
      std::int64_t type_size{};

      // Stack offset referenced
      std::int64_t stack_offset{};
    };

    // The instruction performing the stack-related operation
    llvm::Instruction *instr{nullptr};

    // A list of all the operands that are referencing the stack
    // pointer
    std::vector<Operand> operand_list;
  };

  // A list of instructions that are referencing the stack pointer
  std::vector<Instruction> instruction_list;

  // Lowest SP-relative offset
  std::int64_t lowest_offset{};

  // Highest SP-relative offset
  std::int64_t highest_offset{};

  // Stack frame size
  std::size_t size{};
};

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
  bool Run(llvm::Function &function);

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
                         const StackFrameAnalysis &stack_frame_analysis,
                         std::size_t padding_bytes);

  // Generates a new symbolic stack value
  static Result<llvm::GlobalVariable *, StackAnalysisErrorCode>
  GetStackSymbolicByteValue(llvm::Module &module, std::int32_t offset);

  // Patches the function, replacing the load/store instructions so that
  // they operate on the new stack frame type we generated
  static Result<std::monostate, StackAnalysisErrorCode>
  UpdateFunction(llvm::Function &function,
                 const StackFrameAnalysis &stack_frame_analysis,
                 StackFrameStructureInitializationProcedure init_strategy,
                 std::size_t stack_frame_lower_padding = 0U,
                 std::size_t stack_frame_higher_padding = 0U);

  RecoverStackFrameInformation(ITransformationErrorManager &error_manager,
                               const LifterOptions &options);

  virtual ~RecoverStackFrameInformation() override = default;
};

}  // namespace anvill
