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

#include <anvill/ABI.h>
#include <anvill/Analysis/Utils.h>
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

// Declare a lifted a variable. Will not return `nullptr`.
llvm::Constant *DataLifter::GetOrDeclareData(const GlobalVarDecl &decl,
                                             EntityLifterImpl &lifter_context) {

  const auto &dl = options.module->getDataLayout();
  const auto type = remill::RecontextualizeType(decl.type, context);
  llvm::Constant *found_by_type = nullptr;
  llvm::Constant *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // piece of data at the corresponding address. All data is versioned
  lifter_context.ForEachEntityAtAddress(decl.address, [&](llvm::Constant *v) {
    if (!llvm::isa_and_nonnull<llvm::GlobalValue>(found_by_type)) {
      if (auto ga = llvm::dyn_cast<llvm::GlobalAlias>(v)) {
        if (ga->getValueType() == type) {
          found_by_type = ga;
        }
        found_by_address = ga;

      } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(v)) {
        auto ce_type = llvm::dyn_cast<llvm::PointerType>(ce->getType());
        CHECK_NOTNULL(ce_type);
        if (ce_type->getElementType() == type) {
          found_by_type = ga;
        }
        found_by_address = ga;
      }
    }
  });

  if (found_by_type) {
    return found_by_type;
  }

  auto wrap_with_alias = [&](llvm::Constant *val) -> llvm::Constant * {
    if (!CanBeAliased(val)) {
      return val;
    }

    std::stringstream ss;
    ss << kGlobalAliasNamePrefix << std::hex << decl.address << '_'
       << TranslateType(*type, dl, true);
    const auto name = ss.str();
    const auto ga = llvm::GlobalAlias::create(
        type, 0, llvm::GlobalValue::ExternalLinkage, name, options.module);
    ga->setAliasee(val);

    lifter_context.AddEntity(val, decl.address);
    lifter_context.AddEntity(ga, decl.address);

    return ga;
  };

  if (found_by_address) {

    // We'll use an existing declaration, create a new GEP, and cast as necessary.
    const auto [base, offset] =
        remill::StripAndAccumulateConstantOffsets(dl, found_by_address);
    if (base) {

      // TODO(pag,alessandro): Something related to `remill::BuildPointerToOffset`
      //                       or `remill::BuildIndexes` to return an initialized
      //                       global alias.
      // Key issues:
      //
      //    Need to recursively tell the `lifter_context` about all entities
      //    along the way, kind of like how `FindBaseAndOffset` goes and finds
      //    them.

      if (offset > 0) {

        // dummy IRBuilder to reuse `remill::BuildPointerToOffset`
        llvm::IRBuilder<> ir(options.module->getContext());
        const auto ce = llvm::dyn_cast<llvm::Constant>(
            remill::BuildPointerToOffset(ir, base, offset, type));
        return wrap_with_alias(ce);
      }
    }

    LOG_IF(ERROR, offset < 0)
        << "Found negative offset for variable at " << std::hex << decl.address
        << std::dec << " cast and return to the correct data type.";

    // Fallback to is base is null or offset < 0; bit cast to the
    // correct type
    const auto address_space =
        found_by_address->getType()->getPointerAddressSpace();
    const auto ce = llvm::ConstantExpr::getBitCast(
        found_by_address, type->getPointerTo(address_space));
    lifter_context.AddEntity(ce, decl.address);
    return wrap_with_alias(ce);
  }

  const auto gv = LiftData(decl, lifter_context);
  lifter_context.AddEntity(gv, decl.address);
  return gv;
}

llvm::Constant *DataLifter::LiftData(const GlobalVarDecl &decl,
                                     EntityLifterImpl &lifter_context) {
  const auto &dl = options.module->getDataLayout();
  const auto type = remill::RecontextualizeType(decl.type, context);

  std::vector<uint8_t> bytes;
  llvm::Constant *value = nullptr;
  bool bytes_accessable = false;

  std::stringstream ss2;
  ss2 << kGlobalVariableNamePrefix << std::hex << decl.address << '_'
      << TranslateType(*type, dl, true);

  const auto var_name = ss2.str();
  auto var = options.module->getGlobalVariable(var_name);
  if (var) {
    return var;
  }

  // Inspect the availability of first byte at `decl.address` and append
  // it into the bytes vector
  const auto data_size = dl.getTypeAllocSize(type);
  auto [first_byte, first_byte_avail, first_byte_perms] =
      memory_provider.Query(decl.address);
  if (MemoryProvider::HasByte(first_byte_avail)) {
    bytes.push_back(first_byte);
    bytes_accessable = true;
  }

  // Inspect the read/write permission of bytes and check if it is crossing
  // permission boundaries. Log error in such case
  if (bytes_accessable) {
    for (auto i = 1U; i < data_size; ++i) {
      auto [byte, byte_avail, byte_perms] =
          memory_provider.Query(decl.address + i);
      if (!MemoryProvider::HasByte(byte_avail)) {

        bytes_accessable = false;
        LOG(ERROR) << "Variable at address " << std::hex << decl.address
                   << " crosses into inaccessible bytes (Byte offset " << i
                   << " )!" << std::dec;
        break;
      } else if (first_byte_perms != byte_perms) {
        bytes_accessable = false;
        LOG(ERROR) << "Variable at address " << std::hex << decl.address
                   << " crosses permission (Byte offset " << i << " )!"
                   << std::dec;
        break;
      }

      bytes.push_back(byte);
    }
  }

  if (bytes_accessable) {
    value = lifter_context.value_lifter.Lift(
        std::string_view(reinterpret_cast<char *>(bytes.data()), bytes.size()),
        type, lifter_context, decl.address);
  }

  return new llvm::GlobalVariable(*options.module, type, false,
                                  llvm::GlobalValue::ExternalLinkage, value,
                                  var_name);
}

// Declare a lifted a variable. Will return `nullptr` if the memory is
// not accessible.
llvm::Constant *EntityLifter::DeclareEntity(const GlobalVarDecl &decl) const {

  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      impl->memory_provider->Query(decl.address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail)) {
    return nullptr;
  }

  return impl->data_lifter.GetOrDeclareData(decl, *impl);
}

// Lift a function. Will return `nullptr` if the memory is not accessible.
llvm::Constant *EntityLifter::LiftEntity(const GlobalVarDecl &decl) const {

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
