/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <anvill/LifterOptions.h>
#include <anvill/ValueLifter.h>
#include <anvill/Type.h>
#include <llvm/ADT/APInt.h>
#include <llvm/Support/TypeSize.h>

namespace llvm {
class Constant;
class DataLayout;
class LLVMContext;
class PointerType;
class Type;
}  // namespace llvm
namespace anvill {

struct FunctionDecl;
struct GlobalVarDecl;
class TypeProvider;

class EntityLifterImpl;

// Implementation of the `ValueLifter`.
class ValueLifterImpl {
 public:
  explicit ValueLifterImpl(const LifterOptions &options_);

  // Consume `num_bytes` of bytes from `data`, interpreting them as an integer,
  // and update `data` in place, bumping out the first `num_bytes` of consumed
  // data.
  llvm::APInt ConsumeBytesAsInt(std::string_view &data,
                                unsigned num_bytes) const;

  // Consume `size` bytes of data from `data`, and update `data` in place.
  inline llvm::APInt ConsumeBytesAsInt(std::string_view &data,
                                       llvm::TypeSize size) const {
    return ConsumeBytesAsInt(
        data, static_cast<unsigned>(static_cast<uint64_t>(size)));
  }

  // Interpret `data` as the backing bytes to initialize an `llvm::Constant`
  // of type `type_of_data`. This requires access to `ent_lifter` to be able
  // to lift pointer types that will reference declared data/functions.
  llvm::Constant *Lift(std::string_view data, llvm::Type *type_of_data,
                       EntityLifterImpl &ent_lifter, uint64_t loc_ea) const;

  // Lift pointers at `ea`.
  //
  // NOTE(pag): This returns `nullptr` upon failure to find `ea` as an
  //            entity or plausible entity.
  //
  // NOTE(pag): `hinted_type` can be `nullptr`.
  llvm::Constant *TryGetPointerForAddress(uint64_t ea,
                                          EntityLifterImpl &ent_lifter,
                                          llvm::PointerType *hinted_type) const;

  // Lift pointers at `ea` that is getting referred by the variable at `loc_ea`.
  //
  // Returns an `llvm::GlobalValue *` if the pointer is associated with a
  // known or plausible entity, and an `llvm::Constant *` otherwise.
  llvm::Constant *GetPointer(uint64_t ea, llvm::PointerType *type,
                             EntityLifterImpl &ent_lifter,
                             uint64_t loc_ea) const;

 private:
  llvm::Constant *GetFunctionPointer(const FunctionDecl &decl,
                                     EntityLifterImpl &ent_lifter) const;

  llvm::Constant *GetVarPointer(uint64_t var_ea, uint64_t search_ea,
                                EntityLifterImpl &ent_lifter,
                                llvm::PointerType *ptr_type = nullptr) const;

  const LifterOptions &options;
  const llvm::DataLayout &dl;
  llvm::LLVMContext &context;
  TypeTranslator type_specifier;
};

}  // namespace anvill
