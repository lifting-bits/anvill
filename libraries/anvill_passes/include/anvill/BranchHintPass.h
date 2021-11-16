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

#include <anvill/IntrinsicPass.h>

namespace anvill {


static constexpr auto kFlagIntrinsicPrefix = "__remill_flag_computation";
static constexpr auto kCompareInstrinsicPrefix = "__remill_compare";


template <typename UserFunctionPass, typename Result>
class BranchHintPass : public IntrinsicPass<UserFunctionPass, Result> {
 public:
  static bool isTargetInstrinsic(const llvm::CallInst *callinsn) {
    if (const auto *callee = callinsn->getCalledFunction()) {
      return callee->getName().startswith(kCompareInstrinsicPrefix);
    }

    return false;
  }
};
}  // namespace anvill
