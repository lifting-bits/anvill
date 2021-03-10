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

enum class StateStructureInitializationProcedure : char {

  // Don't do anything with the `alloca State`.
  kNone,

  // Store an LLVM constant aggregate zero into the `alloca State`.
  kZeroes,

  // Store an LLVM undefined value to the `alloca State`.
  kUndef,

  // Should the registers of the `State` structure be initialized from many
  // loads of global variables? If so, then the lifted bitcode takes on the
  // form:
  //
  //      state->rax = __anvill_reg_RAX
  //      state->rbx = __anvill_reg_RBX
  //      ...
  //
  // The purpose here is to show that there are unmodelled dependencies. If
  // this option is `false`, then the `State` structure is *not* initialized.
  kGlobalRegisterVariables,
  kGlobalRegisterVariablesAndZeroes,
  kGlobalRegisterVariablesAndUndef,

  // TODO(pag): Add an option to read values using the `llvm.read_register`
  //            intrinsic.
};

enum class StackFrameStructureInitializationProcedure : char {

  // Don't do anything with the `alloca State`.
  kNone,

  // Store an LLVM constant aggregate zero into the `alloca State`.
  kZeroes,

  // Store an LLVM undefined value to the `alloca State`.
  kUndef,

  // Use symbolic values to initialize each byte in the stack frame
  kSymbolic,
};

// Options that direct the behavior of the code and data lifters.
class LifterOptions {
 public:
  inline explicit LifterOptions(const remill::Arch *arch_,
                                llvm::Module &module_)
      : arch(arch_),
        module(&module_),
        state_struct_init_procedure(StateStructureInitializationProcedure::
                                        kGlobalRegisterVariablesAndZeroes),
        stack_frame_struct_init_procedure(StackFrameStructureInitializationProcedure::
                                        kSymbolic),
        symbolic_program_counter(true),
        symbolic_stack_pointer(true),
        symbolic_return_address(true),
        symbolic_register_types(true),
        store_inferred_register_values(true) {
    CheckModuleContextMatchesArch();
  }

  // What is the architecture being used for lifting?
  const remill::Arch *const arch;

  // Target module into which code will be lifted.
  llvm::Module *const module;

  // The function lifter produces functions with Remill's state structure
  // allocated on the stack. This configuration option determines how the
  // state structure is initialized.
  StateStructureInitializationProcedure state_struct_init_procedure;

  // How the RecoverStackFrameInformation function pass should initialize
  // recovered stack frames
  StackFrameStructureInitializationProcedure stack_frame_struct_init_procedure;

  // Should the program counter in lifted functions be represented with a
  // symbolic expression? If so, then it takes on the form:
  //
  //      (add (ptrtoint __anvill_pc) <address>)
  //
  // Otherwise, a concrete integer is used, i.e. `<address>`.
  bool symbolic_program_counter : 1;

  // Should the stack pointer in lifted functions be represented with a
  // symbolic expression? If so, then it takes on the form:
  //
  //      (ptrtoint __anvill_sp)
  //
  // Otherwise, the initial value of the stack pointer is loaded from a global
  // variable, `__anvill_reg_<stack pointer name>`.
  bool symbolic_stack_pointer : 1;

  // Should the return address in lifted functions be represented with a
  // symbolic expression? If so, then it takes on the form:
  //
  //      (ptrtoint __anvill_ra)
  //
  // Otherwise, the initial value of the return address on entry to a function
  // will be the result of the intrinsic function call:
  //
  //      llvm.returnaddress(0)
  bool symbolic_return_address : 1;

  // Should we ask the type provider to provide us with typing hints for
  // registers on entry to instructions? If so, then if there's a register
  // at a specific address whose type is known, then the lifter performs
  // roughly the following:
  //
  //      state->reg = __anvill_type_func_<hex address>_<type>(state->reg)
  //
  // The `__anvill_type_func_*` functions are basically uninterpreted functions,
  // similar to Remill intrinsic functions, and serves to communicate the
  // equivalent of a bitcast, but where the cast itself cannot be folded
  // away by optimizations.
  //
  // TODO(pag): Convert this into using a global variable approach, like
  //            with `__anvill_pc`. Then it will compose nicely with
  //            `__anvill_sp`, which it currently does not.
  bool symbolic_register_types : 1;

  // If `symbolic_register_types` is `true`, and if the type provider gives us
  // a concrete value that it believes resides in a register at a specific point
  // in time, then should we trust that that value is indeed there and store it
  // into the register? What this looks like is:
  //
  //      ... lifted instructions A ...
  //      state->reg = <constant value>
  //      ... lifted instructions B ...
  //
  // The impact of this option is two-fold. First, from `A`s perspective, any
  // stores to `state->reg` are dead, and can likely be subject to dead store
  // elimination, giving scalar replacement of aggregates and mem2reg and easier
  // time of eliminating accesses to the `State` structure. Second, from `B`s
  // perspective, `state->reg` is now a constant value, allowing store-to-load
  // forwarding.
  bool store_inferred_register_values : 1;

 private:
  LifterOptions(void) = delete;

  void CheckModuleContextMatchesArch(void) const;
};

}  // namespace anvill
