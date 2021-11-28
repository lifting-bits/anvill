/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Specification.h>

#include <map>
#include <unordered_map>
#include <utility>

#include <anvill/Decls.h>
#include <anvill/Providers.h>
#include <anvill/Type.h>

namespace llvm {
class LLVMContext;
namespace json {
class Array;
}  // namespace json
}  // namespace llvm
namespace anvill {

enum class BytePermission : std::uint8_t;

class SpecificationImpl
    : public std::enable_shared_from_this<SpecificationImpl> {
 private:
  friend class Specification;

  SpecificationImpl(void) = delete;
  SpecificationImpl(std::unique_ptr<const remill::Arch> arch_);

  bool ParseRange(const llvm::json::Object *obj, std::stringstream &err);

  bool ParseControlFlowRedirection(
      const llvm::json::Array &redirection_list, std::stringstream &err);

  bool ParseControlFlowTargets(
      const llvm::json::Array &ctrl_flow_target_list, std::stringstream &err);

  const llvm::json::Object *ParseSpecification(
      const llvm::json::Object *obj, std::stringstream &err);

 public:
  ~SpecificationImpl(void);

  // Architecture used by all of the function and global variable declarations.
  const std::unique_ptr<const remill::Arch> arch;

  const TypeDictionary type_dictionary;
  const TypeTranslator type_translator;

  using GlobalVarDeclPtr = std::unique_ptr<GlobalVarDecl>;
  using FunctionDeclPtr = std::unique_ptr<FunctionDecl>;

  // Sorted list of functions and variables.
  std::vector<GlobalVarDeclPtr> variables;
  std::vector<FunctionDeclPtr> functions;

  // List of functions that have been parsed from the JSON spec.
  std::unordered_map<std::uint64_t, const FunctionDecl *> address_to_function;

  // Inverted mapping of byte addresses to the variables containing those
  // addresses.
  std::unordered_map<std::uint64_t, const GlobalVarDecl *> address_to_var;


  // NOTE(pag): We used ordered containers so that any type of round-tripping
  //            to/from JSON ends up getting a consistent order of information.

  // Mapping of addresses to one or more names.
  std::multimap<std::uint64_t, std::string> symbols;

  // Mapping of byte addresses to the byte values and their permissions.
  std::map<std::uint64_t, std::pair<std::uint8_t, BytePermission>> memory;

  // Control-flow redirections.
  std::map<std::uint64_t, std::uint64_t> redirections;

  // De-virtualization targets.
  std::map<std::uint64_t, ControlFlowTargetList> targets;
};

}  // namespace anvill
