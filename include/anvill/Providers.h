/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <llvm/IR/DataLayout.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "Specification.h"
#include "Type.h"

namespace llvm {
class FunctionType;
class LLVMContext;
class Type;
}  // namespace llvm
namespace remill {
class Instruction;
}  // namespace remill
namespace anvill {

// Provides the types of functions, called functions, and accessed data.
class TypeProvider {
 protected:
  llvm::LLVMContext &context;
  llvm::DataLayout data_layout;
  const TypeDictionary type_dictionary;

  explicit TypeProvider(const ::anvill::TypeDictionary &type_dictionary_,
                        const llvm::DataLayout &dl_);

  inline explicit TypeProvider(const TypeTranslator &tt)
      : TypeProvider(tt.Dictionary(), tt.DataLayout()) {}

 public:
  using Ptr = std::shared_ptr<TypeProvider>;

  inline const ::anvill::TypeDictionary &Dictionary(void) const {
    return type_dictionary;
  }

  virtual ~TypeProvider(void);

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  virtual std::optional<FunctionDecl> TryGetFunctionType(
      uint64_t address) const = 0;

  // Try to return the type of a function that has been called from `from_isnt`.
  virtual std::optional<FunctionDecl> TryGetCalledFunctionType(
      const remill::Instruction &from_inst) const;

  // Try to return the type of a function starting at address `to_address`. This
  // type is the prototype of the function. The type can be call site specific,
  // where the call site is `from_inst`.
  virtual std::optional<FunctionDecl> TryGetCalledFunctionType(
      const remill::Instruction &from_inst,
      uint64_t to_address) const;

  // Try to return the variable at given address or containing the address
  virtual std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t address) const = 0;

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  virtual void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>
          typed_reg_cb) const;

  // Creates a type provider that always fails to provide type information.
  static Ptr CreateNull(const ::anvill::TypeDictionary &type_dictionary_,
                        const llvm::DataLayout &dl_);

 private:
  TypeProvider(const TypeProvider &) = delete;
  TypeProvider(TypeProvider &&) noexcept = delete;
  TypeProvider &operator=(const TypeProvider &) = delete;
  TypeProvider &operator=(TypeProvider &&) noexcept = delete;
  TypeProvider(void) = delete;
};


enum class BytePermission : std::uint8_t {
  kUnknown,
  kReadable,
  kReadableWritable,
  kReadableWritableExecutable,
  kReadableExecutable
};

enum class ByteAvailability : std::uint8_t {

  // The address is valid, but a value for the byte is not available.
  kUnknown,

  // The address is not mapped in the address space.
  kUnavailable,

  // The address is mapped and the byte value is available.
  kAvailable
};

// Provides bytes of memory from some source.
class MemoryProvider {
 public:
  virtual ~MemoryProvider(void);

  inline static bool HasByte(ByteAvailability availability) {
    return ByteAvailability::kAvailable == availability;
  }

  inline static bool IsValidAddress(ByteAvailability availability) {
    switch (availability) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kAvailable: return true;
      default: return false;
    }
  }

  inline static bool IsExecutable(BytePermission perms) {
    switch (perms) {
      case BytePermission::kUnknown:
      case BytePermission::kReadableWritableExecutable:
      case BytePermission::kReadableExecutable: return true;
      default: return false;
    }
  }

  // Query for the value, availability, and permission of a byte.
  virtual std::tuple<std::uint8_t, ByteAvailability, BytePermission>
  Query(std::uint64_t address) const = 0;

  // Creates a memory provider that gives access to no memory.
  static std::shared_ptr<MemoryProvider> CreateNull(void);

 protected:
  MemoryProvider(void) = default;

 private:
  MemoryProvider(const MemoryProvider &) = delete;
  MemoryProvider(MemoryProvider &&) noexcept = delete;
  MemoryProvider &operator=(const MemoryProvider &) = delete;
  MemoryProvider &operator=(MemoryProvider &&) noexcept = delete;
};


// Describes a list of targets reachable from a given source address
struct ControlFlowTargetList final {

  // Source address
  std::uint64_t source{};

  // Destination list
  std::vector<std::uint64_t> destination_list;

  // True if this destination list appears to be complete. As a
  // general rule, this is set to true when the target recovery has
  // been completely performed by the disassembler tool
  bool complete{false};
};

class ControlFlowProvider {
 public:
  using Ptr = std::unique_ptr<ControlFlowProvider>;

  // Create a dummy control-flow provider.
  static Ptr CreateNull(void);

  virtual ~ControlFlowProvider(void) = default;

  // Returns a possible redirection for the given target. If there is no
  // redirection then `address` should be returned.
  virtual std::uint64_t GetRedirection(
      const remill::Instruction &from_inst, std::uint64_t to_address) const = 0;

  // Returns a list of targets reachable from the given address
  virtual std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(const remill::Instruction &from_inst) const = 0;

 protected:
  ControlFlowProvider(void) = default;

 private:
  ControlFlowProvider(const ControlFlowProvider &) = delete;
  ControlFlowProvider(ControlFlowProvider &&) noexcept = delete;

  ControlFlowProvider &operator=(const ControlFlowProvider &) = delete;
  ControlFlowProvider &operator=(ControlFlowProvider &&) noexcept = delete;
};

}  // namespace anvill
