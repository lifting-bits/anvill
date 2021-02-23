/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "DataLifter.h"

#include <anvill/Decl.h>
#include <anvill/Lifters/Context.h>
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/TypePrinter.h>

#include <remill/BC/Util.h>

#include <llvm/ADT/APInt.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/Module.h>

#include <glog/logging.h>

#include <sstream>

#include "Context.h"

namespace anvill {
namespace {

// Drill down on the underlying object behind some value/alias, and our byte
// offset away from it.
static std::pair<llvm::Value *, uint64_t>
FindBaseAndOffset(const llvm::DataLayout &dl, llvm::Value *ptr) {
  if (!ptr) {
    return {nullptr, 0};

  } else if (auto var = llvm::dyn_cast<llvm::GlobalVariable>(ptr)) {
    return {var, 0};

  } else if (auto alias = llvm::dyn_cast<llvm::GlobalAlias>(ptr)) {
    if (auto aliasee = alias->getAliasee()) {
      return FindBaseAndOffset(dl, alias);
    } else {
      return {alias, 0};
    }

  } else if (auto gep = llvm::dyn_cast<llvm::GEPOperator>(ptr)) {
    llvm::APInt ap(64, 0);
    auto ret = FindBaseAndOffset(dl, gep->getPointerOperand());
    CHECK(gep->accumulateConstantOffset(dl, ap));
    return {ret.first, ret.second + ap.getZExtValue()};

  } else if (auto bc = llvm::dyn_cast<llvm::BitCastOperator>(ptr)) {
    return FindBaseAndOffset(dl, bc->getOperand(0));

  } else if (auto ac = llvm::dyn_cast<llvm::AddrSpaceCastOperator>(ptr)) {
    return FindBaseAndOffset(dl, bc->getOperand(0));

  } else {
    LOG(ERROR)
        << "Unable to drill down to underlying value for "
        << remill::LLVMThingToString(ptr);
    return {ptr, 0};
  }
}

}  // namespace

DataLifterImpl::~DataLifterImpl(void) {}

DataLifterImpl::DataLifterImpl(const LifterOptions &options_,
                               MemoryProvider &memory_provider_,
                               TypeProvider &type_provider_)
    : options(options_),
      memory_provider(memory_provider_),
      type_provider(type_provider_),
      context(options.module->getContext()) {}

// Declare a lifted a variable. Will not return `nullptr`. One issue that we
// face is that we want to
llvm::GlobalValue *DataLifterImpl::GetOrDeclareData(
    const GlobalVarDecl &decl, ContextImpl &lifter_context) {

  const auto &dl = options.module->getDataLayout();
  const auto type = remill::RecontextualizeType(decl.type, context);
  llvm::GlobalValue *found_by_type = nullptr;
  llvm::GlobalValue *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // piece of data at the corresponding address. All data is versioned
  lifter_context.ForEachEntityAtAddress(
      decl.address,
      [&] (llvm::GlobalValue *gv) {
        if (gv->getValueType() == type) {
          found_by_type = gv;
          found_by_address = gv;

        } else if (llvm::isa<llvm::GlobalVariable>(gv)) {
          found_by_address = gv;

        } else if (!found_by_address) {
          found_by_address = gv;
        }
      });

  if (found_by_type) {
    return found_by_type;
  }

  // We'll use an existing declaration, create a new GEP, and cast as
  // necessary.
  if (auto [base, offset] = FindBaseAndOffset(dl, found_by_address); base) {
    // TODO(pag,alessandro): Something related to `remill::BuildPointerToOffset`
    //                       or `remill::BuildIndexes` to return an initialized
    //                       global alias.
    //
    // Key issues:
    //
    //    Need to recursively tell the `lifter_context` about all entities
    //    along the way, kind of like how `FindBaseAndOffset` goes and finds
    //    them.
  }

  // Create an address- and type-versioned named for this data reference.
  std::stringstream ss;
  ss << "data_" << std::hex << decl.address << '_'
     << TranslateType(*type, dl, true);

  const auto name = ss.str();
  const auto gv = llvm::GlobalAlias::create(
      type, 0, llvm::GlobalValue::ExternalLinkage, name, options.module);

  lifter_context.AddEntity(gv, decl.address);

  // TODO(pag,alessandro): If we're down here then we don't have any other
  //                       aliases for this exact piece of data. However, there
  //                       may we other globals that overlap this piece of data,
  //                       and thus we want to set the initializer based off of
  //                       those globals, similar to what we do in the base/
  //                       offset situation.
  //
  //                       The biggest challenge is a design challenge:
  //                          - What is a reasonable way of getting at this kind
  //                            of information? Do we ask the type provider, and
  //                            if so, how, and what do the results look like?
  //
  //                       The next challenge is data structures:
  //                          - Managing what entities we know about and their
  //                            extents.
  //                          - Do we learn about overlaps as they come up, or
  //                            do we know about them ahead of time? The use of
  //                            aliases enables us to swap out initializers.

  return gv;
}

// Declare a lifted a variable. Will return `nullptr` if the memory is
// not accessible.
llvm::GlobalValue *DataLifterImpl::DeclareData(
    const GlobalVarDecl &decl, ContextImpl &lifter_context) {
  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      memory_provider.Query(decl.address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail)) {
    return nullptr;
  }

  return GetOrDeclareData(decl, lifter_context);
}

// Lift a function. Will return `nullptr` if the memory is not accessible.
llvm::GlobalValue *DataLifterImpl::LiftData(
    const GlobalVarDecl &decl, ContextImpl &lifter_context) {

  // TODO(pag,alessandro): Inspect the pointer returned from `DeclareData`.
  //                       Use `FindBaseAndOffset` to find the base. If the
  //                       base is a global variable with out an initializer,
  //                       then invoke the memory provider to try to build up a
  //                       `std::string` of all of the bytes covered by the
  //                       extent of the global var, *if* that variable's extent
  //                       contains `decl.address`. If bytes aren't readable,
  //                       then fine.

  return DeclareData(decl, lifter_context);
}

// Returns the address of a named function.
std::optional<uint64_t> DataLifterImpl::AddressOfNamedData(
    const std::string &data_name) const {
  return std::nullopt;
}

DataLifter::~DataLifter(void) {}

DataLifter::DataLifter(const Context &lifter_context)
    : impl(lifter_context.impl) {}

// Lifts the raw bytes at address `decl.address`, and using
//
// NOTE(pag): If this function returns `nullptr` then it means that we cannot
//            lift the function (e.g. bad address, or non-executable memory).
llvm::GlobalValue *DataLifter::LiftData(const GlobalVarDecl &decl) const {
  return impl->data_lifter.LiftData(decl, *impl);
}

// Declare the function associated with `decl` in the context's module.
llvm::GlobalValue *DataLifter::DeclareData(const GlobalVarDecl &decl) const {
  return nullptr;
}

}  // namespace anvill
