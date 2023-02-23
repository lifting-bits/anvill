/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "Result.h"
#include "Type.h"

namespace llvm {
class BasicBlock;
class DataLayout;
class Function;
class FunctionType;
class GlobalVariable;
class Module;
class Type;
class Value;
namespace CallingConv {
using ID = unsigned;
}  // namespace CallingConv
}  // namespace llvm
namespace remill {
class Arch;
class IntrinsicTable;
struct Register;
}  // namespace remill
namespace anvill {


struct CodeBlock {
  uint64_t addr;
  uint32_t size;
  std::unordered_set<uint64_t> outgoing_edges;
  // The set of context assignments that occur at the entry point to this block.
  // A block may have specific decoding context properties such as "TM=1" (the thumb bit is set)
  // So we declare the context assignments that occur at the entry point to a block.
  std::unordered_map<std::string, std::uint64_t> context_assignments;
};


class TypeDictionary;


struct LowLoc {
  const remill::Register *reg{nullptr};
  const remill::Register *mem_reg{nullptr};
  std::int64_t mem_offset{0};
  std::optional<std::uint64_t> size{std::nullopt};

  std::uint64_t Size() const;

  bool operator==(const LowLoc &loc) const;
};

// A value, such as a parameter or a return value. Values are resident
// in one of two locations: either in a register, represented by a non-
// nullptr `reg` value, or in memory, at `[mem_reg + mem_offset]`.
//
// In the case of `mem_reg` being used by a parameter or return value,
// we interpret this as meaning: this value is resident in the memory
// address `mem_reg + mem_offset`, using the *initial value* of
// `mem_reg` on entry to the function.
//
// The memory resident value location exists to represent stack-passed
// values. In the case where return-value optimization is implemented
// (in the ABI) as writing into the caller's stack frame, then this
// mechanism can work. However, often times, RVO is implemented by having
// the caller allocate the space, and pass a pointer to that space into
// the callee, and so that should be represented using a parameter.
struct ValueDecl {
  std::vector<LowLoc> oredered_locs;

  TypeSpec spec_type;

  // Type of this value.
  llvm::Type *type{nullptr};
};


// A value declaration corresponding with a named parameter.
struct ParameterDecl : public ValueDecl {

  // Name of the parameter.
  std::string name;
};

// A typed location in memory, that isn't actually code. This roughly
// corresponds with the concept of a global variable, though it doesn't
// actually need to represent data with any kind of "global" visibility.
struct VariableDecl {

  // The type of the memory beginning at `address`. For example, if `address`
  // is `0x10` and the type is a structure containing two integers, then we
  // can also infer that at address `0x10` there is an `int`, and at address
  // `0x14` there is also an `int`.
  llvm::Type *type{nullptr};

  TypeSpec spec_type;

  // Address of this global variable.
  std::uint64_t address{0};

  // Declare this global variable in an LLVM module.
  llvm::GlobalVariable *DeclareInModule(const std::string &name,
                                        llvm::Module &) const;
};

struct OffsetDomain {
  ValueDecl target_value;
  std::int64_t stack_offset;
};

struct ConstantDomain {
  ValueDecl target_value;
  std::uint64_t value;
  bool should_taint_by_pc;
};

struct SpecStackOffsets {
  std::vector<OffsetDomain> affine_equalities;
};

// A declaration for a callable entity.
struct CallableDecl {
 private:
 public:
  void OverrideFunctionTypeWithABIReturnLayout();
  void OverrideFunctionTypeWithABIParamLayout();

  // The architecture from which this function's code derives.
  const remill::Arch *arch{nullptr};

  std::shared_ptr<FunctionType> spec_type;

  // ABI-level type of this function.
  llvm::FunctionType *type{nullptr};

  // Specifies where the return address is located on entry to the function.
  //
  // For example, on x86, this would be at `[esp]`, on amd64, this would be
  // at `[rsp]`, and on aarch64, this would be at `x30`.
  ValueDecl return_address;

  // Value of the stack pointer after the function returns, defined in terms
  // of the entry state of the function. For example, in amd64, it would be
  // typical for the exit return stack pointer to be defined as `RSP + 8`, i.e.
  // equivalent to the entry stack pointer, plus 8 bytes, due to the `ret`
  // having popped off the return address.
  const remill::Register *return_stack_pointer{nullptr};
  std::int64_t return_stack_pointer_offset{0};

  // Parameters.
  //
  // NOTE(pag): In the case of variadic functions in the AMD64 Itanium ABI,
  //            we expect the specification to include `AL` as an explicit
  //            parameter (number of varargs).
  std::vector<ParameterDecl> params;

  // Return values.
  //
  // NOTE(pag): In the case of the AMD64 Itanium ABI, we expect the
  //            specification to include `RDX` as an explicit return
  //            value when the function might throw an exception.
  ValueDecl returns;

  // Is this a noreturn function, e.g. like `abort`?
  bool is_noreturn{false};

  // Is this a variadic function? For example, `printf(const char *format, ...)`
  // is a variadic function.
  bool is_variadic{false};


  // The calling convention of this function.
  llvm::CallingConv::ID calling_convention{0u};

  // Interpret `target` as being the function to call, and call it from within
  // a basic block in a lifted bitcode function. Returns the new value of the
  // memory pointer.
  llvm::Value *CallFromLiftedBlock(llvm::Value *target,
                                   const anvill::TypeDictionary &types,
                                   const remill::IntrinsicTable &intrinsics,
                                   llvm::IRBuilder<> &, llvm::Value *state_ptr,
                                   llvm::Value *mem_ptr) const;

  // Try to create a callable decl from a protobuf default callable decl
  // specification. Returns a string error if something went wrong.
  //
  // NOTE(alex): This is following the same pattern as where we decode an entire
  // specification. Not sure how others feel about this but it does save us from
  // having to expose all the Protobuf stuff in the public headers.
  static anvill::Result<CallableDecl, std::string>
  DecodeFromPB(const remill::Arch *arch, const std::string &pb);
};


// Basic block contexts impose an ordering on live values s.t. shared Parameters between
// live exits and entries
struct BasicBlockVariable {
  ParameterDecl param;
  size_t index;
  bool live_at_entry;
  bool live_at_exit;
};

class BasicBlockContext {
 public:
  virtual ~BasicBlockContext() = default;

  virtual const SpecStackOffsets &GetStackOffsets() const = 0;

  virtual const std::vector<ConstantDomain> &GetConstants() const = 0;

  virtual size_t GetStackSize() const = 0;

  virtual size_t GetMaxStackSize() const = 0;

  virtual size_t GetPointerDisplacement() const = 0;

  virtual uint64_t GetParentFunctionAddress() const = 0;

  virtual ValueDecl ReturnValue() const = 0;

  // Deduplicates locations and ensures there are no overlapping decls
  // A valid parameter list is a set of non overlapping a-locs with distinct names.
  std::vector<BasicBlockVariable> LiveParamsAtEntryAndExit() const;


  std::vector<BasicBlockVariable> LiveBBParamsAtEntry() const;
  std::vector<BasicBlockVariable> LiveBBParamsAtExit() const;


  llvm::StructType *StructTypeFromVars(llvm::LLVMContext &llvm_context) const;

 protected:
  virtual const std::vector<ParameterDecl> &LiveParamsAtEntry() const = 0;
  virtual const std::vector<ParameterDecl> &LiveParamsAtExit() const = 0;
};


/// An abstract stack is made up of components with a bytesize, these components allow us to split the stack at offsets
/// in particular this is helpful for splitting out stack space beyond the locals for things like return addresses
struct StackComponent {
  size_t size;
  llvm::Value *stackptr;
};

class AbstractStack {
 private:
  llvm::LLVMContext &context;
  bool stack_grows_down;
  std::vector<llvm::Type *> stack_types;
  std::vector<StackComponent> components;
  size_t total_size;
  size_t pointer_displacement;

 public:
  // The displacement required to make all offset accesses positive
  size_t GetPointerDisplacement() const {
    return pointer_displacement;
  };


  // The pointer displacement is the size above the zero point of the stack, typically return pointer offset + parameter size
  AbstractStack(llvm::LLVMContext &context,
                std::vector<StackComponent> components, bool stack_grows_down,
                size_t pointer_displacement);

  std::optional<size_t>
  StackOffsetFromStackPointer(std::int64_t stack_off) const;


  std::int64_t StackPointerFromStackOffset(size_t offset) const;


  std::optional<std::int64_t>
  StackPointerFromStackCompreference(llvm::Value *) const;

  static llvm::Type *StackTypeFromSize(llvm::LLVMContext &context, size_t size);

  //llvm::Type *StackType() const;

  std::optional<llvm::Value *>
  PointerToStackMemberFromOffset(llvm::IRBuilder<> &ir,
                                 std::int64_t stack_off) const;
};

struct FunctionDecl;
class SpecBlockContext : public BasicBlockContext {
 private:
  const FunctionDecl &decl;
  SpecStackOffsets offsets;
  std::vector<ConstantDomain> constants;
  std::vector<ParameterDecl> live_params_at_entry;
  std::vector<ParameterDecl> live_params_at_exit;

 public:
  SpecBlockContext(const FunctionDecl &decl, SpecStackOffsets offsets,
                   std::vector<ConstantDomain> constants,
                   std::vector<ParameterDecl> live_params_at_entry,
                   std::vector<ParameterDecl> live_params_at_exit);

  virtual const SpecStackOffsets &GetStackOffsets() const override;

  virtual const std::vector<ConstantDomain> &GetConstants() const override;

  virtual ValueDecl ReturnValue() const override;

  virtual uint64_t GetParentFunctionAddress() const override;

  virtual size_t GetStackSize() const override;

  virtual size_t GetMaxStackSize() const override;

  virtual size_t GetPointerDisplacement() const override;


 protected:
  virtual const std::vector<ParameterDecl> &LiveParamsAtEntry() const override;
  virtual const std::vector<ParameterDecl> &LiveParamsAtExit() const override;
};

// A function decl, as represented at a "near ABI" level. To be specific,
// not all C, and most C++ decls, as written would be directly translatable
// to this. This ought nearly represent how LLVM represents a C/C++ function
// type at the bitcode level, but we go a bit further in explicitness, e.g.
// where a function throwing an exception would -- at least on Linux amd64 --
// be represented as returning two values: one in RAX/XMM0, and one in RDX.
// Similarly, on Linux x86, a 64-bit int returned from a function would be
// represented by the low four bytes in EAX, and the high four bytes in EDX.
//
// NOTE(pag): We associate an architecture with the function decls in the
//            event that we want to handle multiple architectures in the same
//            program (e.g. embedded shellcode for different targets, or
//            Thumb code in an Arm program, or x86 code in a bootloader that
//            brings up amd64 code, etc.).
struct FunctionDecl : public CallableDecl {
  friend class SpecBlockContext;

 public:
  // Address of this function in memory.
  std::uint64_t address{0};

  // The maximum number of bytes of redzone afforded to this function
  // (if it doesn't change the stack pointer, or, for example, writes
  // below the stack pointer on x86/amd64).
  std::uint64_t num_bytes_in_redzone{0};

  bool lift_as_decl{false};
  bool is_extern{false};

  // These are the blocks contained within the function representing the CFG.
  std::unordered_map<std::uint64_t, CodeBlock> cfg;

  std::unordered_map<std::string, ParameterDecl> locals;

  std::unordered_map<std::uint64_t, SpecStackOffsets> stack_offsets;

  std::unordered_map<std::uint64_t, std::vector<ParameterDecl>>
      live_regs_at_entry;

  std::unordered_map<std::uint64_t, std::vector<ParameterDecl>>
      live_regs_at_exit;

  std::unordered_map<std::uint64_t, std::vector<ConstantDomain>>
      constant_values;

  std::uint64_t stack_depth;

  std::uint64_t maximum_depth;

  std::int64_t ret_ptr_offset{0};

  std::int64_t parameter_offset{0};

  std::size_t parameter_size{0};

  // Declare this function in an LLVM module.
  llvm::Function *DeclareInModule(std::string_view name, llvm::Module &) const;

  // Create a function declaration from an LLVM function.
  inline static Result<FunctionDecl, std::string>
  Create(llvm::Function &func,
         const std::unique_ptr<const remill::Arch> &arch) {
    return Create(func, arch.get());
  }

  size_t GetPointerDisplacement() const;

  // Create a function declaration from an LLVM function.
  static Result<FunctionDecl, std::string> Create(llvm::Function &func,
                                                  const remill::Arch *arch);

  SpecBlockContext GetBlockContext(std::uint64_t addr) const;

  void
  AddBBContexts(std::unordered_map<uint64_t, SpecBlockContext> &contexts) const;
};

// A call site decl, as represented at a "near ABI" level. This is like a
// `FunctionDecl`, but is specific to a call site. Thus, it represents where
// the parameters of a function called by a call site reside, where the return
// values will reside, etc., and all with respect to the register state on
// entry to the called function. The purpose of call site specific declarations
// is that
struct CallSiteDecl : public CallableDecl {
 public:
  // Address of the call site.
  std::uint64_t address{0};

  // Address of the function containing this call site.
  std::uint64_t function_address{0};
};

}  // namespace anvill
