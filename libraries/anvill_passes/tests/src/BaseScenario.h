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

#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "SplitStackFrameAtReturnAddress.h"

namespace anvill {

class BaseScenario final {
 public:
  using Ptr = std::unique_ptr<BaseScenario>;

  static bool Create(Ptr &obj);
  ~BaseScenario();

  void GenerateEmptyEntryBlock();

  llvm::AllocaInst *GenerateStackFrameAllocationEntryBlock();

  SplitStackFrameAtReturnAddress::StoreInstAndOffsetPair
  GenerateStackFrameWithRetnIntrinsicEntryBlock();

  llvm::StructType *GenerateStackFrameType();

  llvm::Function *Function() const;
  llvm::LLVMContext &Context() const;

  BaseScenario(const BaseScenario &) = delete;
  BaseScenario &operator=(const BaseScenario &) = delete;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  BaseScenario();
};

}  // namespace anvill
