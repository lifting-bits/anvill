/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Decl.h>
#include <anvill/Program.h>
#include <anvill/TypeProvider.h>
#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Type.h>
#include <remill/BC/Util.h>

namespace anvill {
namespace {

class NullTypeProvider final : public TypeProvider {
 public:
  virtual ~NullTypeProvider(void) = default;

  using TypeProvider::TypeProvider;

  // Try to return the type of a function starting at address `address`. This
  // type is the prototype of the function.
  std::optional<FunctionDecl> TryGetFunctionType(uint64_t) const final {
    return std::nullopt;
  }

  std::optional<GlobalVarDecl>
  TryGetVariableType(uint64_t) const final {
    return std::nullopt;
  }

 private:
  NullTypeProvider(void) = delete;
};

}  // namespace

TypeProvider::~TypeProvider(void) {}

// Try to return the type of a function starting at address `to_address`. This
// type is the prototype of the function. The type can be call site specific,
// where the call site is `from_inst`.
std::optional<FunctionDecl> TypeProvider::TryGetCalledFunctionType(
    const remill::Instruction &from_inst, uint64_t to_address) const {
  auto decl = TryGetCalledFunctionType(from_inst);
  if (!decl) {
    return TryGetFunctionType(to_address);
  } else {
    return decl;
  }
}

// Try to return the type of a function that has been called from `from_isnt`.
std::optional<FunctionDecl> TypeProvider::TryGetCalledFunctionType(
    const remill::Instruction &) const {
  return std::nullopt;
}

TypeProvider::TypeProvider(const TypeDictionary &type_dictionary_,
                           const llvm::DataLayout &dl_)
    : context(type_dictionary_.u.named.bool_->getContext()),
      dl(dl_),
      type_dictionary(type_dictionary_) {}

// Try to get the type of the register named `reg_name` on entry to the
// instruction at `inst_address` inside the function beginning at
// `func_address`.
void TypeProvider::QueryRegisterStateAtInstruction(
    uint64_t, uint64_t,
    std::function<void(const std::string &, llvm::Type *,
                       std::optional<uint64_t>)>) const {}

// Creates a type provider that always fails to provide type information.
TypeProvider::Ptr TypeProvider::CreateNull(
    const TypeDictionary &type_dictionary_,
    const llvm::DataLayout &dl_) {
  return std::make_shared<NullTypeProvider>(type_dictionary_, dl_);
}

}  // namespace anvill
