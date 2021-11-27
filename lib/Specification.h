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
  SpecificationImpl(std::shared_ptr<llvm::LLVMContext> context_,
              std::unique_ptr<const remill::Arch> arch_);

  bool ParseRange(const llvm::json::Object *obj, std::stringstream &err);

  bool ParseControlFlowRedirection(
      const llvm::json::Array &redirection_list, std::stringstream &err);

  bool ParseControlFlowTargets(
      const llvm::json::Array &ctrl_flow_target_list, std::stringstream &err);

  const llvm::json::Object *ParseSpecification(
      const llvm::json::Object *obj, std::stringstream &err);

 public:
  ~SpecificationImpl(void);

  // Context used by all things.
  const std::shared_ptr<llvm::LLVMContext> context;

  // Architecture used by all of the function and global variable declarations.
  const std::unique_ptr<const remill::Arch> arch;

  const TypeDictionary type_dictionary;
  const TypeTranslator type_translator;

  // NOTE(pag): We used ordered containers so that any type of round-tripping
  //            to/from JSON ends up getting a consistent order of information.

  // List of functions that have been parsed from the JSON spec.
  std::map<std::uint64_t, FunctionDecl> functions;

  // List of variables that have been parsed from the JSON spec.
  std::map<std::uint64_t, GlobalVarDecl> variables;

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
