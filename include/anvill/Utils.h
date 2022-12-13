/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <remill/Arch/Arch.h>

#include <cstdint>
#include <memory>
#include <string>

namespace llvm {
class BasicBlock;
class Instruction;
class IRBuilderBase;
class Module;
class Value;
class Type;
}  // namespace llvm
namespace remill {
class Arch;
class IntrinsicTable;
}  // namespace remill
namespace anvill {

struct ValueDecl;
class TypeDictionary;

// Adapt `src` to another type (likely an integer type) that is `dest_type`.
llvm::Value *AdaptToType(llvm::IRBuilderBase &ir, llvm::Value *src,
                         llvm::Type *dest_type);

// Creates a `sub_<address>` name from an address
std::string CreateFunctionName(std::uint64_t addr);

// Creates a `data_<address>` name from an address
std::string CreateVariableName(std::uint64_t addr);

// Looks for any constant expressions in the operands of `inst` and unfolds
// them into other instructions in the same block.
void UnfoldConstantExpressions(llvm::Instruction *inst);

// Copies metadata from the source to destination if both values are instructions.
void CopyMetadataTo(llvm::Value *src, llvm::Value *dst);

// Returns `true` if it looks like `val` is the program counter.
bool IsProgramCounter(llvm::Module *module, llvm::Value *val);

// Returns `true` if it looks like `val` is the stack counter.
bool IsStackPointer(llvm::Module *module, llvm::Value *val);

// Returns `true` if it looks like `val` is the return address.
bool IsReturnAddress(llvm::Module *module, llvm::Value *val);

class StackPointerResolverImpl;
class StackPointerResolver {
 private:
  std::unique_ptr<StackPointerResolverImpl> impl;

 public:
  ~StackPointerResolver(void);
  explicit StackPointerResolver(llvm::Module *module);

  // Returns `true` if it looks like `val` is derived from a symbolic stack
  // pointer representation.
  bool IsRelatedToStackPointer(llvm::Value *) const;
};

// Returns `true` if it looks like `val` is derived from a symbolic stack
// pointer representation.
bool IsRelatedToStackPointer(llvm::Module *module, llvm::Value *val);

// Returns `true` if `val` looks like it is backed by a definition, and thus can
// be the aliasee of an `llvm::GlobalAlias`.
bool CanBeAliased(llvm::Value *val);

// Produce one or more instructions in `in_block` to load and return
// the lifted value associated with `decl`.
llvm::Value *LoadLiftedValue(const ValueDecl &decl, const TypeDictionary &types,
                             const remill::IntrinsicTable &intrinsics,
                             llvm::BasicBlock *in_block, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr);

llvm::Value *LoadLiftedValue(const ValueDecl &decl, const TypeDictionary &types,
                             const remill::IntrinsicTable &intrinsics,
                             llvm::IRBuilder<> &ir, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr);


void CloneIntrinsicsFromModule(llvm::Module &from, llvm::Module &into);

void StoreNativeValueToRegister(llvm::Value *native_val,
                                const remill::Register *reg,
                                const TypeDictionary &types,
                                const remill::IntrinsicTable &intrinsics,
                                llvm::IRBuilder<> &ir, llvm::Value *state_ptr);

void StoreNativeValueToRegister(llvm::Value *native_val,
                                const remill::Register *reg,
                                const TypeDictionary &types,
                                const remill::IntrinsicTable &intrinsics,
                                llvm::BasicBlock *in_block,
                                llvm::Value *state_ptr);


llvm::Value *StoreNativeValue(llvm::Value *native_val, const ValueDecl &decl,
                              const TypeDictionary &types,
                              const remill::IntrinsicTable &intrinsics,
                              llvm::IRBuilder<> &ir, llvm::Value *state_ptr,
                              llvm::Value *mem_ptr);


// Produce one or more instructions in `in_block` to store the
// native value `native_val` into the lifted state associated
// with `decl`.
llvm::Value *StoreNativeValue(llvm::Value *native_val, const ValueDecl &decl,
                              const TypeDictionary &types,
                              const remill::IntrinsicTable &intrinsics,
                              llvm::BasicBlock *in_block,
                              llvm::Value *state_ptr, llvm::Value *mem_ptr);

std::optional<uint64_t> GetBasicBlockAddr(llvm::Function *func);

}  // namespace anvill
