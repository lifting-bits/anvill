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

#include <llvm/IR/PassManager.h>
#include <llvm/Pass.h>

namespace anvill {

// This pass unrolls constant expressions that involve the stack pointer into instructions so that
// RecoverStackInformation can replace the stack pointer with its stack representation.

// define i1 @slice() local_unnamed_addr #2 {
//     %1 = call zeroext i1 (i1, ...) @__remill_flag_computation_sign(i1 zeroext icmp slt (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -12), i32 0), i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -12)) #5
//     ret i1 %1
// }

// Becomes:
// define i1 @slice() local_unnamed_addr {
//   %1 = ptrtoint i8* @__anvill_sp to i32
//   %2 = add i32 %1, -12
//   %3 = icmp slt i32 %2, 0
//   %4 = ptrtoint i8* @__anvill_sp to i32
//   %5 = add i32 %4, -12
//   %6 = call zeroext i1 (i1, ...) @__remill_flag_computation_sign(i1 zeroext %3, i32 %5)
//   ret i1 %6
// }

class RemoveStackPointerCExprs final
    : public llvm::PassInfoMixin<RemoveStackPointerCExprs> {
 public:
  RemoveStackPointerCExprs(void) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &AM);
};

}  // namespace anvill
