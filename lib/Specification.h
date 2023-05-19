/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/Declarations.h>
#include <anvill/Providers.h>
#include <anvill/Specification.h>
#include <anvill/Type.h>
#include <specification.pb.h>

#include <functional>
#include <map>
#include <unordered_map>
#include <utility>

#include "anvill/Passes/BasicBlockPass.h"

namespace llvm {
class LLVMContext;
}  // namespace llvm
namespace anvill {

enum class BytePermission : std::uint8_t;

class SpecificationImpl
    : public std::enable_shared_from_this<SpecificationImpl> {
 private:
  friend class Specification;

  SpecificationImpl(void) = delete;
  SpecificationImpl(std::unique_ptr<const remill::Arch> arch_, std::string image_name_, uint64_t image_base_);

  Result<std::vector<std::string>, std::string>
  ParseSpecification(const ::specification::Specification &obj);

 public:
  ~SpecificationImpl(void);

  // Architecture used by all of the function and global variable declarations.
  const std::unique_ptr<const remill::Arch> arch;

  std::string image_name;
  std::uint64_t image_base;

  const TypeDictionary type_dictionary;
  const TypeTranslator type_translator;

  using VariableDeclPtr = std::unique_ptr<VariableDecl>;
  using FunctionDeclPtr = std::unique_ptr<FunctionDecl>;
  using CallSiteDeclPtr = std::unique_ptr<CallSiteDecl>;

  // Sorted list of functions, variables, and call sites.
  std::vector<VariableDeclPtr> variables;
  std::vector<FunctionDeclPtr> functions;
  std::vector<CallSiteDeclPtr> call_sites;

  // List of functions that have been parsed from the JSON spec.
  std::unordered_map<std::uint64_t, const FunctionDecl *> address_to_function;

  // Inverted mapping of byte addresses to the variables containing those
  // addresses.
  std::unordered_map<std::uint64_t, const VariableDecl *> address_to_var;


  // NOTE(pag): We used ordered containers so that any type of round-tripping
  //            to/from JSON ends up getting a consistent order of information.

  // Mapping of addresses to one or more names.
  std::multimap<std::uint64_t, std::string> symbols;

  // Mapping of byte addresses to the byte values and their permissions.
  std::map<std::uint64_t, std::pair<std::uint8_t, BytePermission>> memory;

  // Control-flow redirections.
  std::map<std::uint64_t, std::uint64_t> redirections;

  // Call-site specific target information.
  std::map<std::pair<std::uint64_t, std::uint64_t>, const CallSiteDecl *>
      loc_to_call_site;

  // Sorted list of jumps, calls, returns and other control flow overrides
  std::vector<Jump> jumps;
  std::vector<Call> calls;
  std::vector<Return> returns;
  std::vector<Misc> misc_overrides;

  std::unordered_map<std::uint64_t, ControlFlowOverride> control_flow_overrides;
};

}  // namespace anvill
