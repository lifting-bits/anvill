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
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "Declarations.h"
#include "Specification.h"
#include "Type.h"

namespace llvm {
class FunctionType;
class LLVMContext;
class Type;
}  // namespace llvm
namespace remill {
class Instruction;
enum ArchName : uint32_t;
}  // namespace remill
namespace anvill {

class TypeProvider {
 public:
  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  virtual std::optional<FunctionDecl>
  TryGetFunctionType(uint64_t address) const = 0;

  // Try to return the type of a function that has been called from `from_isnt`.
  virtual std::optional<CallableDecl>
  TryGetCalledFunctionType(uint64_t function_address,
                           const remill::Instruction &from_inst) const;

  // Try to return the type of a function starting at address `to_address`. This
  // type is the prototype of the function. The type can be call site specific,
  // where the call site is `from_inst`.
  virtual std::optional<CallableDecl>
  TryGetCalledFunctionType(uint64_t function_address,
                           const remill::Instruction &from_inst,
                           uint64_t to_address) const;

  // Try to return the variable at given address or containing the address
  virtual std::optional<VariableDecl>
  TryGetVariableType(uint64_t address,
                     llvm::Type *hinted_value_type=nullptr) const = 0;

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  virtual void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>
          typed_reg_cb) const = 0;

  virtual const ::anvill::TypeDictionary &Dictionary(void) const = 0;

  virtual ~TypeProvider() = default;
};

// Provides the types of functions, called functions, and accessed data.
class BaseTypeProvider : public TypeProvider {
 protected:
  llvm::LLVMContext &context;
  const TypeDictionary type_dictionary;

 public:
  explicit BaseTypeProvider(const ::anvill::TypeDictionary &type_dictionary_);

  inline explicit BaseTypeProvider(const TypeTranslator &tt)
      : BaseTypeProvider(tt.Dictionary()) {}

  const ::anvill::TypeDictionary &Dictionary(void) const override;

  virtual ~BaseTypeProvider(void);

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>
          typed_reg_cb) const override;

 private:
  BaseTypeProvider(const TypeProvider &) = delete;
  BaseTypeProvider(TypeProvider &&) noexcept = delete;
  BaseTypeProvider &operator=(const TypeProvider &) = delete;
  BaseTypeProvider &operator=(TypeProvider &&) noexcept = delete;
  BaseTypeProvider(void) = delete;
};

class NullTypeProvider : public BaseTypeProvider {
 public:
  virtual ~NullTypeProvider(void) = default;

  using BaseTypeProvider::BaseTypeProvider;

  std::optional<FunctionDecl> TryGetFunctionType(uint64_t) const override;
  std::optional<VariableDecl> TryGetVariableType(
      uint64_t, llvm::Type *hinted_value_type=nullptr) const override;
};

// Delegates to an underlying tye provider to provide the data. Derived from
// this class to stack one provider on top of another.
class ProxyTypeProvider : public TypeProvider {
 private:
  const TypeProvider &deleg;

 public:
  explicit ProxyTypeProvider(const TypeProvider &deleg);

  virtual ~ProxyTypeProvider(void) = default;

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  std::optional<FunctionDecl>
  TryGetFunctionType(uint64_t address) const override;

  // Try to return the type of a function that has been called from `from_isnt`.
  std::optional<CallableDecl>
  TryGetCalledFunctionType(uint64_t function_address,
                           const remill::Instruction &from_inst) const override;

  // Try to return the type of a function starting at address `to_address`. This
  // type is the prototype of the function. The type can be call site specific,
  // where the call site is `from_inst`.
  std::optional<CallableDecl>
  TryGetCalledFunctionType(uint64_t function_address,
                           const remill::Instruction &from_inst,
                           uint64_t to_address) const override;

  // Try to return the variable at given address or containing the address
  std::optional<VariableDecl>
  TryGetVariableType(
      uint64_t address, llvm::Type *hinted_value_type=nullptr) const override;

  // Try to get the type of the register named `reg_name` on entry to the
  // instruction at `inst_address` inside the function beginning at
  // `func_address`.
  void QueryRegisterStateAtInstruction(
      uint64_t func_address, uint64_t inst_address,
      std::function<void(const std::string &, llvm::Type *,
                         std::optional<uint64_t>)>
          typed_reg_cb) const override;

  const ::anvill::TypeDictionary &Dictionary(void) const override;
};

// Allow for one to specify "reasonable" default declarations for call sites.
//
// NOTE(pag): This class does *not* bring in any smarts in terms of determining
//            if what's being asked of it /should/ be a function. A higher-level
//            type provider ought to delegate to the `SpecificationTypeProvider`
//            on whether or not the queried function addresses are "viable
//            functions."
class DefaultCallableTypeProviderImpl;
class DefaultCallableTypeProvider : public ProxyTypeProvider {
 private:
  const std::unique_ptr<DefaultCallableTypeProviderImpl> impl;

 public:
  virtual ~DefaultCallableTypeProvider(void);

  // Initialize this type provider with a default architecture and a preferred
  // type provider `deleg`.
  explicit DefaultCallableTypeProvider(remill::ArchName default_arch,
                                       const TypeProvider &deleg);

  // Set `decl` to the default callable type for `arch`.
  void SetDefault(remill::ArchName arch, CallableDecl decl);

  // Try to return the type of a function that has been called from `from_isnt`.
  std::optional<CallableDecl>
  TryGetCalledFunctionType(uint64_t function_address,
                           const remill::Instruction &from_inst) const override;

  std::optional<anvill::FunctionDecl>
  TryGetFunctionType(uint64_t address) const override;
};

// Provides the types of functions, called functions, and accessed data.
class SpecificationTypeProvider : public BaseTypeProvider {
 private:
  std::shared_ptr<SpecificationImpl> impl;

 public:
  virtual ~SpecificationTypeProvider(void);

  explicit SpecificationTypeProvider(const Specification &spec);

  // Try to return the type of a function that has been called from `from_isnt`.
  std::optional<CallableDecl>
  TryGetCalledFunctionType(uint64_t function_address,
                           const remill::Instruction &from_inst) const override;

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  std::optional<anvill::FunctionDecl>
  TryGetFunctionType(uint64_t address) const override;

  std::optional<anvill::VariableDecl>
  TryGetVariableType(uint64_t address,
                     llvm::Type *hinted_value_type=nullptr) const override;

 private:
  SpecificationTypeProvider(void) = delete;
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

 protected:
  MemoryProvider(void) = default;

 private:
  MemoryProvider(const MemoryProvider &) = delete;
  MemoryProvider(MemoryProvider &&) noexcept = delete;
  MemoryProvider &operator=(const MemoryProvider &) = delete;
  MemoryProvider &operator=(MemoryProvider &&) noexcept = delete;
};

class NullMemoryProvider : public MemoryProvider {
 public:
  virtual ~NullMemoryProvider(void) = default;

  std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) const override;
};

// Provider of memory wrapping around an `Specification`.
class SpecificationMemoryProvider : public MemoryProvider {
 public:
  virtual ~SpecificationMemoryProvider(void);

  explicit SpecificationMemoryProvider(const Specification &spec);

  std::tuple<uint8_t, anvill::ByteAvailability, anvill::BytePermission>
  Query(uint64_t address) const final;

 private:
  SpecificationMemoryProvider(void) = delete;

  const std::shared_ptr<SpecificationImpl> impl;
};

class ControlFlowProvider {
 public:
  virtual ~ControlFlowProvider(void) = default;

  // Returns a possible redirection for the given target. If there is no
  // redirection then `address` should be returned.
  virtual std::uint64_t GetRedirection(const remill::Instruction &from_inst,
                                       std::uint64_t to_address) const = 0;

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

class NullControlFlowProvider : public ControlFlowProvider {
 public:
  virtual ~NullControlFlowProvider(void) = default;

  std::uint64_t GetRedirection(const remill::Instruction &,
                               std::uint64_t address) const override;

  std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(const remill::Instruction &) const override;
};

class SpecificationControlFlowProvider : public anvill::ControlFlowProvider {
 private:
  std::shared_ptr<SpecificationImpl> impl;

 public:
  virtual ~SpecificationControlFlowProvider(void);

  explicit SpecificationControlFlowProvider(const Specification &spec);

  std::uint64_t GetRedirection(const remill::Instruction &from_inst,
                               std::uint64_t address) const final;

  std::optional<anvill::ControlFlowTargetList>
  TryGetControlFlowTargets(const remill::Instruction &from_inst) const final;
};


}  // namespace anvill
