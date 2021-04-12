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

#include "ParameterDecl.h"
#include "TypedRegisterDecl.h"

#include <llvm/IR/CallingConv.h>

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/Support/JSON.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/IntrinsicTable.h>

namespace anvill {

// A function decl, as represented at a "near ABI" level. To be specific,
// not all C, and most C++ decls, as written would be directly translatable
// to this. This ought nearly represent how LLVM represents a C/C++ function
// type at the bitcode level, but we go a bit further in explicitness, e.g.
// where a function throwing an exception would -- at least on Linux amd64 --
// be represented as returning two values: one in RAX/XMM0, and one in RDX.
// Similarly, on Linux x86, a 64-bit int returned from a function would be
// represented by the low four bytes in EAX, and the high four bytes in EDX.
//
// NOTE(pag): We associate an architecture with the function decls in the
//            event that we want to handle multiple architectures in the same
//            program (e.g. embedded shellcode for different targets, or
//            Thumb code in an Arm program, or x86 code in a bootloader that
//            brings up amd64 code, etc.).
struct FunctionDecl {
 public:
  // The architecture from which this function's code derives.
  const remill::Arch *arch{nullptr};

  // Address of this function in memory.
  uint64_t address{0};

  // ABI-level type of this function.
  llvm::FunctionType *type{nullptr};

  // Specifies where the return address is located on entry to the function.
  //
  // For example, on x86, this would be at `[esp]`, on amd64, this would be
  // at `[rsp]`, and on aarch64, this would be at `x30`.
  ValueDecl return_address;

  // Value of the stack pointer after the function returns, defined in terms
  // of the entry state of the function. For example, in amd64, it would be
  // typical for the exit return stack pointer to be defined as `RSP + 8`, i.e.
  // equivalent to the entry stack pointer, plus 8 bytes, due to the `ret`
  // having popped off the return address.
  const remill::Register *return_stack_pointer{nullptr};
  int64_t return_stack_pointer_offset{0};

  // Parameters.
  //
  // NOTE(pag): In the case of variadic functions in the AMD64 Itanium ABI,
  //            we expect the specification to include `AL` as an explicit
  //            parameter (number of varargs).
  std::vector<ParameterDecl> params;

  // Map program addresses to remill registers and type information.
  std::unordered_map<uint64_t, std::vector<TypedRegisterDecl>> reg_info;

  // Return values.
  //
  // NOTE(pag): In the case of the AMD64 Itanium ABI, we expect the
  //            specification to include `RDX` as an explicit return
  //            value when the function might throw an exception.
  std::vector<ValueDecl> returns;

  // Is this a noreturn function, e.g. like `abort`?
  bool is_noreturn{false};

  // Is this a variadic function?
  bool is_variadic{false};

  // The calling convention of this function.
  llvm::CallingConv::ID calling_convention{llvm::CallingConv::C};

  // The mazimum number of bytes of redzone afforded to this function
  // (if it doesn't change the stack pointer, or, for example, writes
  // below the stack pointer on x86/amd64).
  uint64_t num_bytes_in_redzone{0};

  // Declare this function in an LLVM module.
  llvm::Function *DeclareInModule(const std::string &name, llvm::Module &,
                                  bool allow_unowned = false) const;

  // Create a call to this function with name `name` from within a basic block
  // in a lifted bitcode function. Returns the new value of the memory pointer.
  llvm::Value *CallFromLiftedBlock(const std::string &name,
                                   const remill::IntrinsicTable &intrinsics,
                                   llvm::BasicBlock *block,
                                   llvm::Value *state_ptr, llvm::Value *mem_ptr,
                                   bool allow_unowned = false) const;

  // Serialize this function decl to JSON.
  llvm::json::Object SerializeToJSON(const llvm::DataLayout &dl) const;

  // Create a function declaration from an LLVM function.
  inline static llvm::Expected<FunctionDecl>
  Create(llvm::Function &func, const remill::Arch::ArchPtr &arch) {
    return Create(func, arch.get());
  }

  // Create a function declaration from an LLVM function.
  static llvm::Expected<FunctionDecl> Create(llvm::Function &func,
                                             const remill::Arch *arch);

  // The owner of this decl. Only set if this is valid.
  void *owner{nullptr};
};

}  // namespace anvill
