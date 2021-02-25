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

#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

namespace anvill {

class SplitStackFrameAtReturnAddress final : public llvm::FunctionPass {
 public:
  static SplitStackFrameAtReturnAddress *Create();

  bool runOnFunction(llvm::Function &function) final;

  virtual llvm::StringRef getPassName() const override;

  // Returns the name of the stack frame type for the given function
  static std::string
  GetFunctionStackFrameTypeName(const llvm::Function &function);

  // Returns the stack frame type for the given function
  static bool GetFunctionStackFrameType(const llvm::StructType *&frame_type,
                                        const llvm::Function &function);

  // Returns the `alloca` instruction for the function's stackframe, or
  // nullptr if not found
  static llvm::AllocaInst *GetStackFrameAllocaInst(llvm::Function &function);

  // Returns the first `call` instruction to the llvm.returnaddress intrinsic
  // in the entry block or nullptr if not found
  static const llvm::CallInst *
  GetReturnAddressInstrinsicCall(const llvm::Function &function);

  // A store instruction and the offset into the structure being written
  using StoreInstAndOffsetPair =
      std::pair<const llvm::StoreInst *, std::int64_t>;

  // Returns a list of StoreInstAndOffsetPair that identify stores
  // instructions that are saving the value of the llvm.returnaddress
  // intrinsic and the alloca inst that allocates the stack frame
  static bool GetRetnAddressStoreInstructions(
      std::vector<StoreInstAndOffsetPair> &store_off_pairs,
      llvm::AllocaInst *&alloca_inst, llvm::Function &function);

  // Given an offset into the specified StructType, it returns the matching
  // struct element index
  static bool StructOffsetToElementIndex(std::uint32_t &elem_index,
                                         const llvm::Module *module,
                                         const llvm::StructType *struct_type,
                                         std::int64_t offset);

  // Takes the function's stack frame type and splits it into three parts, isolating
  // the element at the given index in its own structure
  static bool SplitStackFrameTypeAtOffset(
      std::vector<llvm::StructType *> &stack_frame_parts,
      const llvm::Function &function, std::int64_t offset,
      const llvm::StructType *stack_frame_type);

  // Takes the function's stack frame and splits it by patching the IR
  static bool SplitStackFrameAtOffset(llvm::Function &function,
                                      std::int64_t offset,
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
  static char ID;

  SplitStackFrameAtReturnAddress(void) : llvm::FunctionPass(ID) {}
};

}  // namespace anvill
