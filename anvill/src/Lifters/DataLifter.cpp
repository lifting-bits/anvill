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
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/TypePrinter.h>
#include <glog/logging.h>
#include <llvm/ADT/APInt.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/Module.h>
#include <remill/BC/Util.h>

#include <sstream>

#include "EntityLifter.h"

namespace anvill {

DataLifter::~DataLifter(void) {}

DataLifter::DataLifter(const LifterOptions &options_,
                       MemoryProvider &memory_provider_,
                       TypeProvider &type_provider_)
    : options(options_),
      memory_provider(memory_provider_),
      type_provider(type_provider_),
      context(options.module->getContext()) {}

// Declare a lifted a variable. Will not return `nullptr`. One issue that we
// face is that we want to
llvm::GlobalValue *
DataLifter::GetOrDeclareData(const GlobalVarDecl &decl,
                             EntityLifterImpl &lifter_context) {

  const auto &dl = options.module->getDataLayout();
  const auto type = remill::RecontextualizeType(decl.type, context);
  llvm::GlobalValue *found_by_type = nullptr;
  llvm::GlobalValue *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // piece of data at the corresponding address. All data is versioned
  lifter_context.ForEachEntityAtAddress(
      decl.address, [&](llvm::GlobalValue *gv) {
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
  const auto [base, offset] = remill::StripAndAccumulateConstantOffsets(
      dl, found_by_address);
  if (base) {

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
  const auto ga = llvm::GlobalAlias::create(
      type, 0, llvm::GlobalValue::ExternalLinkage, name, options.module);

  lifter_context.AddEntity(ga, decl.address);

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

  // !!! TEMPORARY because we need all aliasees to have an initializer!!!
  std::stringstream ss2;
  ss2 << "var_" << std::hex << decl.address << '_'
      << TranslateType(*type, dl, true);

  // TODO(akshay): use `dl` to figure out the size in bytes of the type. Make
  //               a `std::string` and initialize it to that size. Use the
  //               `MemoryProvider` to query each byte offset from
  //               `decl.address`, and if the byte is available, then write it
  //               into the string. Inspect the permissions as you read/write
  //               bytes. Be careful about crossing permission boundaries; i.e.
  //               if we cross from writable into non-writable, then we should
  //               treat that as a failure to get the needed bytes. Log a
  //               warning/error, and we'll treat the var as an uninitialized
  //               external. Use that same permissions tracking to set whether
  //               or not the global var is constant. Try to factor this out
  //               into one or more functions and not do it all right here.
  //               Finally, if and when all bytes are read, and no permission
  //               boundaries are crossed, go and invoke the data lifter.
  const auto gv = new llvm::GlobalVariable(
      *options.module, type, false, llvm::GlobalValue::ExternalLinkage,
      llvm::Constant::getNullValue(type), ss2.str());

  ga->setAliasee(gv);
  lifter_context.AddEntity(gv, decl.address);

  return ga;
}

// Declare a lifted a variable. Will return `nullptr` if the memory is
// not accessible.
llvm::GlobalValue *
EntityLifter::DeclareEntity(const GlobalVarDecl &decl) const {

  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      impl->memory_provider->Query(decl.address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail)) {
    return nullptr;
  }

  return impl->data_lifter.GetOrDeclareData(decl, *impl);
}

// Lift a function. Will return `nullptr` if the memory is not accessible.
llvm::GlobalValue *EntityLifter::LiftEntity(const GlobalVarDecl &decl) const {

  // TODO(pag,alessandro): Inspect the pointer returned from `DeclareData`.
  //                       Use `FindBaseAndOffset` to find the base. If the
  //                       base is a global variable with out an initializer,
  //                       then invoke the memory provider to try to build up a
  //                       `std::string` of all of the bytes covered by the
  //                       extent of the global var, *if* that variable's extent
  //                       contains `decl.address`. If bytes aren't readable,
  //                       then fine.

  return impl->data_lifter.GetOrDeclareData(decl, *impl);
}

}  // namespace anvill
