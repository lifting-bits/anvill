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

#include "GlobalVarDecl.h"

#include "Lifters/DeclLifter.h"
#include <llvm_utils/TypePrinter.h>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include "Arch/Arch.h"

namespace anvill {

// Declare this global variable in an LLVM module.
llvm::GlobalVariable *
GlobalVarDecl::DeclareInModule(const std::string &name,
                               llvm::Module &target_module,
                               bool allow_unowned) const {
  if (!allow_unowned && !owner) {
    return nullptr;
  }

  auto &context = target_module.getContext();
  auto var_type = remill::RecontextualizeType(type, context);

  auto existing_var = target_module.getGlobalVariable(name);
  if (existing_var && existing_var->getValueType() == var_type) {
    return existing_var;
  }

  return new llvm::GlobalVariable(target_module, var_type, false,
                                  llvm::GlobalValue::ExternalLinkage, nullptr,
                                  name);
}

}  // namespace anvill
