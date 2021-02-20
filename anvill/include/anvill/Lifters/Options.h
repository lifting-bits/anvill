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

namespace llvm {
class Module;
}  // namespace llvm
namespace remill {
class Arch;
}  // namespace remill
namespace anvill {

// Options that direct the behavior of the code and data lifters.
class LifterOptions {
 public:
  inline explicit LifterOptions(const remill::Arch *arch_,
                                llvm::Module &module_)
      : arch(arch_),
        module(&module_),
        symbolic_program_counter(true),
        symbolic_stack_pointer(true),
        symbolic_return_address(true) {
    CheckModuleContextMatchesArch();
  }

  // What is the architecture being used for lifting?
  const remill::Arch * const arch;

  // Target module into which code will be lifted.
  llvm::Module * const module;

  // Should the program counter in lifted functions be represented with a
  // symbolic expression? If so, then it takes on the form:
  //
  //      (add (ptrtoint __anvill_pc) <address>)
  //
  // Otherwise, a concrete integer is used, i.e. `<address>`.
  bool symbolic_program_counter:1;

  // Should the stack pointer in lifted functions be represented with a
  // symbolic expression? If so, then it takes on the form:
  //
  //      (ptrtoint __anvill_sp)
  //
  // Otherwise, the initial value of the stack pointer is loaded from a global
  // variable, `__anvill_reg_<stack pointer name>`.
  bool symbolic_stack_pointer:1;

  // Should the return address in lifted functions be represented with a
  // symbolic expression? If so, then it takes on the form:
  //
  //      (ptrtoint __anvill_ra)
  //
  // Otherwise, the initial value of the return address on entry to a function
  // will be the result of the intrinsic function call:
  //
  //      llvm.returnaddress(0)
  bool symbolic_return_address:1;

 private:
  LifterOptions(void) = delete;

  void CheckModuleContextMatchesArch(void) const;
};

}  // namespace anvill
