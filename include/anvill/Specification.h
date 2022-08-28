/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "JSON.h"
#include "Result.h"

namespace llvm {
class BasicBlock;
class DataLayout;
class Function;
class FunctionType;
class GlobalVariable;
class LLVMContext;
class Module;
class Type;
class Value;
namespace CallingConv {
using ID = unsigned;
}  // namespace CallingConv
namespace json {
class Object;
class Value;
}  // namespace json
}  // namespace llvm
namespace remill {
class Arch;
class IntrinsicTable;
struct Register;
}  // namespace remill
namespace anvill {

class SpecificationControlFlowProvider;
class SpecificationImpl;
class SpecificationMemoryProvider;
class SpecificationTypeProvider;
class TypeDictionary;
class TypeTranslator;

// Describes a list of targets reachable from a given source address. This tells
// us where the flows go, not the mechanics of how they get there.
struct ControlFlowTargetList final {

  // Address of an indirect jump.
  std::uint64_t address{};

  // List of addresses targeted by the indirect jump. This is a set, and thus
  // does not track the multiplicity of those targets, nor the order that they
  // appear in any kind of binary-specific structure (e.g. a jump table). That
  // is, a given indirect jump may target the same address in multiple different
  // ways (e.g. multiple `case` labels in a `switch` statement that share the
  // same body).

  /// The addresses map a target to a given context mapping.
  std::map<std::uint64_t, std::map<std::string, uint64_t>> target_addresses;


  // True if this destination list appears to be complete. As a
  // general rule, this is set to true when the target recovery has
  // been completely performed by the disassembler tool.
  bool is_complete{false};
};

// Represents the data pulled out of a JSON (sub-)program specification.
class Specification {
 private:
  friend class SpecificationControlFlowProvider;
  friend class SpecificationMemoryProvider;
  friend class SpecificationTypeProvider;

  Specification(void) = delete;

  std::shared_ptr<SpecificationImpl> impl;

  explicit Specification(std::shared_ptr<SpecificationImpl> impl_);

 public:
  ~Specification(void);

  // Return the architecture used by this specification.
  std::shared_ptr<const remill::Arch> Arch(void) const;

  // Return the type dictionary used by this specification.
  const ::anvill::TypeDictionary &TypeDictionary(void) const;

  // Return the type translator used by this specification.
  const ::anvill::TypeTranslator &TypeTranslator(void) const;

  // Try to create a program from a JSON specification. Returns a string error
  // if something went wrong.
  static anvill::Result<Specification, JSONDecodeError>
  DecodeFromJSON(llvm::LLVMContext &context, const llvm::json::Value &val);

  // Try to encode the specification into JSON.
  anvill::Result<llvm::json::Object, JSONEncodeError> EncodeToJSON(void);

  // Return the function beginning at `address`, or an empty `shared_ptr`.
  std::shared_ptr<const FunctionDecl> FunctionAt(std::uint64_t address) const;

  // Return the global variable beginning at `address`, or an empty `shared_ptr`.
  std::shared_ptr<const VariableDecl> VariableAt(std::uint64_t address) const;

  // Return the global variable containing `address`, or an empty `shared_ptr`.
  std::shared_ptr<const VariableDecl>
  VariableContaining(std::uint64_t address) const;

  // Call `cb` on each symbol in the spec, until `cb` returns `false`.
  void ForEachSymbol(
      std::function<bool(std::uint64_t, const std::string &)> cb) const;

  // Call `cb` on each function in the spec, until `cb` returns `false`.
  void ForEachFunction(
      std::function<bool(std::shared_ptr<const FunctionDecl>)> cb) const;

  // Call `cb` on each variable in the spec, until `cb` returns `false`.
  void ForEachVariable(
      std::function<bool(std::shared_ptr<const VariableDecl>)> cb) const;

  // Call `cb` on each call site in the spec, until `cb` returns `false`.
  void ForEachCallSite(
      std::function<bool(std::shared_ptr<const CallSiteDecl>)> cb) const;

  // Call `cb` on each control-flow target list, until `cb` returns `false`.
  void ForEachControlFlowTargetList(
      std::function<bool(std::shared_ptr<const ControlFlowTargetList>)> cb)
      const;

  // Call `cb` on each control-flow redirection, until `cb` returns `false`.
  void ForEachControlFlowRedirect(
      std::function<bool(std::uint64_t, std::uint64_t)> cb) const;

  inline bool operator==(const Specification &that) const noexcept {
    return impl.get() == that.impl.get();
  }

  inline bool operator!=(const Specification &that) const noexcept {
    return impl.get() == that.impl.get();
  }
};

}  // namespace anvill
