/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
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

#include <llvm/Pass.h>
#include <llvm/IR/PassManager.h>

namespace anvill {

class StackFrameRecoveryOptions;

// Splits the stack frame type of the given function, isolating the
// llvm.returnaddress (if present) in its own StructType to allow for
// further optimization passes to better simplify/eliminate stack
// accesses.
class SplitStackFrameAtReturnAddress final
    : public llvm::PassInfoMixin<SplitStackFrameAtReturnAddress> {
 private:
  const StackFrameRecoveryOptions &options;
 public:

  inline explicit SplitStackFrameAtReturnAddress(
      const StackFrameRecoveryOptions &options_)
      : options(options_) {}

  // Function pass entry point
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &fam);


  static llvm::StringRef name(void);
};

}  // namespace anvill
