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

//
// The main goal of this pass is to isolate the return address value
// saved on the stack frame in its own structure, so that additional
// function passes can more easily eliminate clean up the code and
// eliminate unneeded structures from the stack frame.
//
// The following is an example scenario
//
//     int add(int *a, int *b) {
//       return *a + *b;
//     }
//
//     int main(int argc, char **) {
//       int x = argc;
//       return add(&x, &x);
//     }
//
// The stack frame may look like this:
//
//     struct StackFrame final {
//       int argc;
//       void *ret_addr_of_main;
//       int x;
//     };
//
// Passing the `x` pointer to the call causes LLVM to not be able to rule
// out the possibility that the `add` function may in fact decide to access
// other members in the stack frame (like StackFrame::argc). This prevents
// further optimizations to simplify the code.
//
// In order to fix this problem, this function pass splits the StackFrame
// type while also updating all its usages throughout the code.
//
// Here's how this example scenario is handled:
//
//     struct StackFrame_part0 final {
//       int argc;
//     };
//
//     struct StackFrame_part1 final {
//       void *ret_addr_of_main;
//     };
//
//     struct StackFrame_part2 final {
//       int x;
//     };
//

#pragma once

#include "BaseFunctionPass.h"

namespace anvill {

// Function pass outcome
enum class StackFrameSplitErrorCode {

  // The pass has either succeeded or decided that the function
  // does not need any patching
  Success,

  // The function possesses features that the pass does not support
  NotSupported,

  // An internal error, most likely a logic bug
  InternalError,

  // An error has occurred while trying to track instructions/uses
  InstructionTrackingError,

  // The structure offset is not valid, and could not be mapped
  // back to a valid StructType element index
  StackFrameOffsetError,

  // The stack frame type for this function is missing
  MissingFunctionStackFrameType,

  // The instruction responsible for allocating the stack frame
  // was not found
  StackFrameAllocationNotFound,
};

// A store instruction and the offset into the structure being written
using StoreInstAndOffsetPair = std::pair<const llvm::StoreInst *, std::int64_t>;

// Output data for GetRetnAddressStoreInstructions
struct RetnAddressStoreInstructions final {

  // A list of store instructions and offsets that operate
  // on the stack frame allocated by the `alloca_inst` instruction
  std::vector<StoreInstAndOffsetPair> store_off_pairs;

  // This is the instruction that allocates the stack frame
  // of the function
  llvm::AllocaInst *alloca_inst{nullptr};
};

using SuccessOrStackSplitError =
    Result<std::monostate, StackFrameSplitErrorCode>;

// Splits the stack frame type of the given function, isolating the
// llvm.returnaddress (if present) in its own StructType to allow for
// further optimization passes to better simplify/eliminate stack
// accesses.
class SplitStackFrameAtReturnAddress final
    : public BaseFunctionPass<SplitStackFrameAtReturnAddress> {

 public:
  // Creates a new SplitStackFrameAtReturnAddress object
  static SplitStackFrameAtReturnAddress *
  Create(ITransformationErrorManager &error_manager);

  // Function pass entry point
  bool Run(llvm::Function &function);

  // Returns the pass name
  virtual llvm::StringRef getPassName(void) const override;

  // Executes the function pass logic
  Result<bool, StackFrameSplitErrorCode> execute(llvm::Function &function);

  // Returns the name of the stack frame type for the given function
  static std::string
  GetFunctionStackFrameTypeName(const llvm::Function &function);

  // Returns the stack frame type for the given function
  static Result<const llvm::StructType *, StackFrameSplitErrorCode>
  GetFunctionStackFrameType(const llvm::Function &function);

  // Returns the `alloca` instruction for the function's stackframe, or
  // nullptr if not found
  static Result<llvm::AllocaInst *, StackFrameSplitErrorCode>
  GetStackFrameAllocaInst(llvm::Function &function);

  // Returns the first `call` instruction to the llvm.returnaddress intrinsic
  // in the entry block or nullptr if not found
  static const llvm::CallInst *
  GetReturnAddressInstrinsicCall(const llvm::Function &function);

  // Returns a list of StoreInstAndOffsetPair that identify stores
  // instructions that are saving the value of the llvm.returnaddress
  // intrinsic and the alloca inst that allocates the stack frame
  static Result<RetnAddressStoreInstructions, StackFrameSplitErrorCode>
  GetRetnAddressStoreInstructions(llvm::Function &function);

  // Given an offset into the specified StructType, it returns the matching
  // struct element index
  static Result<std::uint32_t, StackFrameSplitErrorCode>
  StructOffsetToElementIndex(const llvm::Module *module,
                             const llvm::StructType *struct_type,
                             std::int64_t offset);

  // Takes the function's stack frame type and splits it into three parts, isolating
  // the element at the given index in its own structure
  static Result<std::vector<llvm::StructType *>, StackFrameSplitErrorCode>
  SplitStackFrameTypeAtOffset(const llvm::Function &function,
                              std::int64_t offset,
                              const llvm::StructType *stack_frame_type);

  // Takes the function's stack frame and splits it by patching the IR
  static SuccessOrStackSplitError
  SplitStackFrameAtOffset(llvm::Function &function, std::int64_t offset,
                          llvm::AllocaInst *orig_frame_alloca);

  // Tracks down all the direct and indirect users of source_instr that are
  // of type InstructionType
  template <typename InstructionType>
  static std::vector<InstructionType *>
  TrackUsersOf(const llvm::Instruction *source_instr) {

    std::vector<const llvm::Value *> pending_queue{source_instr};
    std::vector<InstructionType *> user_instr_list;

    do {
      auto queue = std::move(pending_queue);
      pending_queue.clear();

      for (const auto &instr : queue) {
        for (const auto &use : instr->uses()) {
          const auto user = use.getUser();

          auto user_instr = llvm::dyn_cast<InstructionType>(user);
          if (user_instr != nullptr) {
            user_instr_list.push_back(user_instr);
          } else {
            pending_queue.push_back(user);
          }
        }
      }
    } while (!pending_queue.empty());

    return user_instr_list;
  }

 private:
  SplitStackFrameAtReturnAddress(ITransformationErrorManager &error_manager);
  virtual ~SplitStackFrameAtReturnAddress(void) override = default;
};

}  // namespace anvill