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

#include "FunctionDecl.h"
#include "GlobalVarDecl.h"
#include "ParameterDecl.h"
#include "TypedRegisterDecl.h"
#include "ValueDecl.h"

#include <llvm_utils/Utils.h>

namespace anvill {

template <typename T>
static llvm::Error CheckValueDecl(const T &decl, llvm::LLVMContext &context,
                                  const char *desc, const FunctionDecl &tpl) {
  if (!decl.type) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Missing LLVM type information for %s "
        "in function declaration at %lx",
        desc, tpl.address);

  } else if (decl.type->isFunctionTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is a function type; "
        "did you mean to use a function pointer type?",
        desc, tpl.address);

  } else if (decl.type->isVoidTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is a void type; "
        "did you mean to use a void pointer type, or to "
        "exclude it entirely?",
        desc, tpl.address);

  } else if (&(decl.type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is associated "
        "with a different LLVM context than the function's "
        "architecture",
        desc, tpl.address);

  } else if (decl.reg && decl.mem_reg) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "A %s cannot be resident in both a "
        "register (%s) and a memory location (%s + %ld) in "
        "function declaration at %lx",
        desc, decl.reg->name.c_str(), decl.mem_reg->name.c_str(),
        decl.mem_offset, tpl.address);

  } else if (decl.reg && &(decl.reg->type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is associated "
        "with a different LLVM context than the %s's "
        "register location",
        desc, tpl.address, desc);

  } else if (decl.mem_reg && &(decl.mem_reg->type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is associated "
        "with a different LLVM context than the %s's "
        "memory location base register",
        desc, tpl.address, desc);

  } else if (decl.mem_reg && !decl.mem_reg->type->isIntegerTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Type of memory base register of %s in function "
        "declaration at %lx must be integral",
        desc, tpl.address);
  }

  if (decl.reg && decl.type) {
    auto reg_size = llvm_utils::EstimateSize(tpl.arch, decl.reg->type);
    auto type_size = llvm_utils::EstimateSize(tpl.arch, decl.type);
    if (reg_size < type_size) {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Size of register %s of %s in function "
          "declaration at %lx is too small (%lu bytes) for "
          "value of size %lu bytes",
          decl.reg->name.c_str(), desc, tpl.address, reg_size, type_size);
    }
  }

  return llvm::Error::success();
}

}
