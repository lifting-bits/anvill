/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/ADT/ArrayRef.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>

namespace llvm {
class Constant;
class DataLayout;
class Function;
class GlobalValue;
class IntegerType;
class IRBuilderBase;
class Module;
class PointerType;
class Type;
class Value;
}  // namespace llvm
namespace remill {
class Arch;
struct Register;
}  // namespace remill
namespace anvill {

struct FunctionDecl;
struct VariableDecl;

class ControlFlowProvider;
class EntityLifterImpl;
class FunctionLifter;
class LifterOptions;
class MemoryProvider;
class TypeDictionary;
class TypeProvider;
class ValueLifter;
class ValueLifterImpl;

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

  // Not initializing the stack frame may or may not have the same
  // meaning as initializing it with the kUndef strategy. The exact
  // behavior depends on external factors such as compiler switches
  // and version
  kNone,

  // Always initialize stack frames with zeroes
  kZeroes,

  // Explicitly mark stack frames as Undef; compared to kNone, the
  // effect of this initialization is more predictable and won't
  // change with different compiler switches or versions
  kUndef,

  // Use symbolic values to initialize each byte in the stack frame. This
  // is useful to track how the stack frame is used and also allows us to
  // generate bitcode that can be compiled while also communicating the
  // missing/unmodeled input dependencies
  kSymbolic,
};

class StackFrameRecoveryOptions {
 public:
  // How the RecoverBasicStackFrame function pass should initialize
  // recovered stack frames
  StackFrameStructureInitializationProcedure stack_frame_struct_init_procedure{
      StackFrameStructureInitializationProcedure::kSymbolic};

  //
  // Stack frame padding is useful to support red zones for ABIs that support
  // them. See https://en.wikipedia.org/wiki/Red_zone_(computing) for more
  // information
  //

  // How many bytes of padding should be added after recovered stack frames.
  // If the stack grows down, then this padding would represent the size of
  // the redzone.
  std::uint64_t stack_frame_lower_padding{0u};

  // How many bytes of padding should be added before recovered stack frames.
  // If the stack grows down, then this padding would represent bytes of the
  // caller's stack frame.
  std::uint64_t stack_frame_higher_padding{0u};

  // What is the maximum stack frame size to consider?
  std::uint64_t max_stack_frame_size{8192u};

  // Size in bytes of stack frame "words". If zero then it is interpreted as
  // being the size of a pointer (in bytes).
  unsigned stack_frame_word_size{0u};

  // The name to use for the metadata on pointers to describe the offset from
  // the stack pointer of a given pointer value.
  const char *stack_offset_metadata_name{nullptr};

  // Direction of stack growth.
  //
  // TODO(pag): Initialize this via the arch or the options.
  bool stack_grows_down{true};

  // Is the initial value of the stack pointer negative or positive? This
  // influences things like the somewhat arbitrary flags computed from the
  // stack pointer (NOTE: flags testing alignment of stack pointer aren't
  // arbitrary, but aren't well-defined either). The signedness of the stack
  // pointer is often relevant to whether or not we're in user mode or kernel
  // mode.
  //
  // TODO(pag): Initialize this via the arch or the options. E.g. user mode
  //            Linux for 32-bit might use negative numbers.
  bool stack_pointer_is_negative{false};
};

// Options that direct the behavior of the code and data lifters.
class LifterOptions {
 public:
  // Initialize the stack pointer with a constant expression of the form:
  //
  //    (ptrtoint __anvill_sp)
  //
  static llvm::Value *SymbolicStackPointerInitWithOffset(
      llvm::IRBuilderBase &ir, const remill::Register *sp_reg,
      uint64_t func_address, std::int64_t offset);

  static llvm::Value *SymbolicStackPointerInit(llvm::IRBuilderBase &ir,
                                               const remill::Register *sp_reg,
                                               uint64_t func_address);

  // Initialize the program counter with a constant expression of the form:
  //
  //    (add (ptrtoint __anvill_pc), <addr>)
  //
  static llvm::Value *SymbolicProgramCounterInit(llvm::IRBuilderBase &ir,
                                                 const remill::Register *pc_reg,
                                                 uint64_t func_address);

  // Initialize the return address with a constant expression of the form:
  //
  //    (ptrtoint __anvill_ra)
  //
  static llvm::Value *SymbolicReturnAddressInit(llvm::IRBuilderBase &ir,
                                                llvm::IntegerType *type,
                                                uint64_t func_address);

  // Initialize the return address with the result of:
  //
  //    call llvm.returnaddress(0)
  //
  static llvm::Value *ConcreteReturnAddressInit(llvm::IRBuilderBase &ir,
                                                llvm::IntegerType *type,
                                                uint64_t func_address);


  inline explicit LifterOptions(
      const remill::Arch *arch_, llvm::Module &module_,
      const TypeProvider &type_provider_,
      const ControlFlowProvider &control_flow_provider_,
      const MemoryProvider &memory_provider_)
      : arch(arch_),
        module(&module_),
        type_provider(type_provider_),
        control_flow_provider(control_flow_provider_),
        memory_provider(memory_provider_),
        state_struct_init_procedure(StateStructureInitializationProcedure::
                                        kGlobalRegisterVariablesAndZeroes),
        program_counter_init_procedure(SymbolicProgramCounterInit),
        stack_pointer_init_procedure(SymbolicStackPointerInit),
        return_address_init_procedure(SymbolicReturnAddressInit),
        add_breakpoints(false),
        track_provenance(false),
        //TODO(ian): This should be initialized by an OS + arch pair
        stack_pointer_is_signed(false),
        should_remove_anvill_pc(true) {
    CheckModuleContextMatchesArch();
  }

  // What is the architecture being used for lifting?
  //
  // TODO(pag): Remove this; decls have architectures.
  const remill::Arch *const arch;

  // Target module into which code will be lifted.
  llvm::Module *const module;

  // Return the data layout associated with the lifter options.
  const llvm::DataLayout &DataLayout(void) const;

  const TypeProvider &type_provider;
  const ControlFlowProvider &control_flow_provider;
  const MemoryProvider &memory_provider;

  // Dictionary of types to be used by the type specifier. Any time we load
  // or store types into memory, we may be operating on wrapped types, e.g.
  // a structure wrapping an `i32`, signalling that we're actually dealing with
  // a signed integer. To know what is what, we need to know the dictionary of
  // interpretable types.
  const ::anvill::TypeDictionary &TypeDictionary(void) const;

  // The function lifter produces functions with Remill's state structure
  // allocated on the stack. This configuration option determines how the
  // state structure is initialized.
  StateStructureInitializationProcedure state_struct_init_procedure;

  // Name of metadata to attach to LLVM instructions, so that they can be
  // related to original program counters in the binary.
  const char *pc_metadata_name{nullptr};

  // Should the program counter in lifted functions be represented with a
  // symbolic expression? If so, then it takes on the form:
  //
  //      (add (ptrtoint __anvill_pc) <address>)
  //
  // Otherwise, a concrete integer is used, i.e. `<address>`.
  std::function<llvm::Value *(llvm::IRBuilderBase &, const remill::Register *,
                              uint64_t)>
      program_counter_init_procedure;

  // Procedure for producing an initial value of the stack pointer on entry
  // to a function. An `IRBuilderBase` is provided for building values within
  // the entry block of the function at the given address.
  std::function<llvm::Value *(llvm::IRBuilderBase &, const remill::Register *,
                              uint64_t)>
      stack_pointer_init_procedure;

  // Procedure for producing an initial value of the return address on entry
  // to a function. An `IRBuilderBase` is provided for building values within
  // the entry block of the function at the given address.
  std::function<llvm::Value *(llvm::IRBuilderBase &, llvm::IntegerType *,
                              uint64_t)>
      return_address_init_procedure;

  StackFrameRecoveryOptions stack_frame_recovery_options;

  // Add so-called breakpoint calls. These can be useful for visually
  // identifying the general provenance of lifted bitcode with respect to
  // machine code instruction addresses. If the bitcode is compiled, then
  // the introduced `breakpoint_NNN` calls act as convenient locations on
  // which to place debugger breakpoints, so as to stop execution roughly
  // prior to that instruction's execution.
  bool add_breakpoints : 1;

  // Enable data provenance gathering via uninterpreted function calls, in a
  // way that will survive LLVM optimizations.
  bool track_provenance : 1;

  // Should we treat the stack pointer as signed when simplifying sign flags.
  bool stack_pointer_is_signed : 1;

  bool should_remove_anvill_pc : 1;

  // Inline calls to basic block functions
  bool inline_basic_blocks : 1;

 private:
  LifterOptions(void) = delete;

  void CheckModuleContextMatchesArch(void) const;
};

// Lifting context for ANVILL. The lifting context keeps track of the options
// used for lifting, the module into which lifted objects are placed, and
// a the mapping between lifted objects and their original addresses in the
// binary.
class EntityLifter {
 public:
  ~EntityLifter(void);

  explicit EntityLifter(const LifterOptions &options);

  // Assuming that `entity` is an entity that was lifted by this `EntityLifter`,
  // then return the address of that entity in the binary being lifted.
  std::optional<uint64_t> AddressOfEntity(llvm::Constant *entity) const;

  // Return the options being used by this entity lifter.
  const LifterOptions &Options(void) const;

  // Return the data layout associated with this entity lifter.
  const llvm::DataLayout &DataLayout(void) const;

  // Return a reference to the memory provider used by this entity lifter.
  const MemoryProvider &MemoryProvider(void) const;

  // Return a reference to the type provider for this entity lifter.
  const TypeProvider &TypeProvider(void) const;

  // Lift a function and return it. Returns `nullptr` if there was a failure.
  llvm::Function *LiftEntity(const FunctionDecl &decl) const;

  // Lift a function and return it. Returns `nullptr` if there was a failure.
  llvm::Function *DeclareEntity(const FunctionDecl &decl) const;

  // Lift a variable and return it. Returns `nullptr` if there was a failure.
  llvm::Constant *LiftEntity(const VariableDecl &decl) const;

  // Lift a variable and return it. Returns `nullptr` if there was a failure.
  llvm::Constant *DeclareEntity(const VariableDecl &decl) const;

  EntityLifter(const EntityLifter &) = default;
  EntityLifter(EntityLifter &&) noexcept = default;
  EntityLifter &operator=(const EntityLifter &) = default;
  EntityLifter &operator=(EntityLifter &&) noexcept = default;

 private:
  friend class DataLifter;
  friend class FunctionLifter;
  friend class ValueLifter;
  friend class ValueLifterImpl;

  inline EntityLifter(const std::shared_ptr<EntityLifterImpl> &impl_)
      : impl(impl_) {}

  EntityLifter(void) = default;

  std::shared_ptr<EntityLifterImpl> impl;
};

class ValueLifter {
 public:
  ~ValueLifter(void);

  ValueLifter(const EntityLifter &entity_lifter_);

  // Interpret `data` as the backing bytes to initialize an `llvm::Constant`
  // of type `type_of_data`. `loc_ea`, if non-null, is the address at which
  // `data` appears.
  llvm::Constant *Lift(llvm::ArrayRef<uint8_t> data,
                       llvm::Type *type_of_data) const;

  // Interpret `ea` as being a pointer to a value of type `value_type` in the
  // address space `address_space`.
  //
  // Returns an `llvm::Constant *` if the pointer is associated with a
  // known or plausible entity, and an `nullptr` otherwise.
  llvm::Constant *Lift(std::uint64_t ea, llvm::Type *value_type,
                       unsigned address_space = 0u) const;

 private:
  std::shared_ptr<EntityLifterImpl> impl;
};

}  // namespace anvill
