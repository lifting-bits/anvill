/*
 * Copyright (c) 2020 Trail of Bits, Inc.
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

#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/BC/Version.h>

namespace anvill {
llvm::InlineResult InlineFunction(llvm::CallBase *call,
                                  llvm::InlineFunctionInfo &info) {
#if LLVM_VERSION_NUMBER < LLVM_VERSION(11, 0)
  return llvm::InlineFunction(call, info);
#else
  return llvm::InlineFunction(*call, info);
#endif
}
}  // namespace anvill
