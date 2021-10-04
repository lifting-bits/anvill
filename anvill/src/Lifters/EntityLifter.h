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

#pragma once

#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Lifters/Options.h>
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Providers/TypeProvider.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/ValueMap.h>

#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "DataLifter.h"
#include "FunctionLifter.h"
#include "ValueLifter.h"

namespace llvm {
class GlobalValue;
class Function;
}  // namespace llvm
namespace anvill {

class ValueLifter;
class ValueLifterImpl;

// An entity lifter is responsible for lifting functions and data (variables)
// into a target LLVM module.
class EntityLifterImpl {
 public:
  ~EntityLifterImpl(void);

  explicit EntityLifterImpl(
      const LifterOptions &options_,
      const std::shared_ptr<MemoryProvider> &mem_provider_,
      const std::shared_ptr<TypeProvider> &type_provider_);

  // Tells the entity lifter that `entity` is the lifted function/data at
  // `address`. There is some collusion between the `Context`, the
  // `FunctionLifter`, the `DataLifter`, and the `ValueLifter` to ensure their
  // view of the world remains consistent.
  void AddEntity(llvm::Constant *entity, uint64_t address);

  // Applies a callback `cb` to each entity at a specified address.
  void ForEachEntityAtAddress(uint64_t address,
                              std::function<void(llvm::Constant *)> cb) const;

  // Assuming that `entity` is an entity that was lifted by this `EntityLifter`,
  // then return the address of that entity in the binary being lifted.
  std::optional<uint64_t> AddressOfEntity(llvm::Constant *entity) const;
  const std::shared_ptr<MemoryProvider> getMemoryProvider();  
 
 private:
  friend class EntityLifter;
  friend class DataLifter;
  friend class FunctionLifter;
  friend class ValueLifter;
  friend class ValueLifterImpl;

  EntityLifterImpl(void) = delete;

  // Options used to guide how lifting should occur.
  const LifterOptions &options;

  // Provider of memory when asking for bytes for instructions or data.
  const std::shared_ptr<MemoryProvider> memory_provider;

  // Provider of type information when asking for function prototypes.
  const std::shared_ptr<TypeProvider> type_provider;

  // Lifts initializers of global variables. Talks with the `data_lifter`
  // and the `function_lifter` when its trying to resolve cross-references
  // embedded in initialziers.
  ValueLifterImpl value_lifter;

  // Used to lift functions.
  FunctionLifter function_lifter;

  // Used to lift data references. Talks with the `value_lifter` to initialize
  // global variables.
  DataLifter data_lifter;

  // Maps native code addresses to lifted entities. The lifted entities reside
  // in the `options.module` module.
  // address_to_entity may become out of date with entity_to_address when a constant is removed by an optimization.
  // The llvm::WeakTrackingVH will still exist in the smallset for the address, however, since address_to_entity is only accessed through ForEachEntityAtAddress
  // this function checks if the WeakTrackingVH has been nulled and only invokes the callback on non-null value handles.
  // This effectively removes a VH from the SmallSet when it is removed from the ValueMap.
  std::unordered_map<uint64_t, llvm::SmallSet<llvm::WeakTrackingVH, 10>>
      address_to_entity;

<<<<<<< HEAD
  // Maps lifted entities to native addresses. The value map acts as a weak reference to the entity.
  llvm::ValueMap<llvm::Constant *, uint64_t> entity_to_address;
=======
  // Maps lifted entities to native addresses. The lifted
  std::unordered_map<llvm::Constant *, uint64_t> entity_to_address;

  
>>>>>>> 76b9d6f (added pass to optimizer)
};

}  // namespace anvill
