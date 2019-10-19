/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <cstdint>
#include <functional>
#include <memory>

#include <llvm/Support/Error.h>

namespace anvill {

// Represents a range of bytes, whose data is found in the range
// `[begin, end)`.
struct ByteRange {
  uint64_t address{0};
  const uint8_t *begin{nullptr};
  const uint8_t *end{nullptr};
  bool is_readable{false};
  bool is_writeable{false};
  bool is_executable{false};
};

class Program;

// Abstraction around a byte, its location, and metadata
// associated with it.
struct Byte {
 public:
  struct Impl;

  ~Byte(void) = default;
  Byte(void) = default;
  Byte(const Byte &) = default;
  Byte(Byte &&) noexcept = default;
  Byte &operator=(const Byte &) = default;
  Byte &operator=(Byte &&) noexcept = default;

  inline operator bool(void) const {
    return impl != nullptr;
  }

  inline uint64_t Address(void) const {
    return addr;
  }

  inline bool IsReadable(void) const {
    return impl ? IsReadableImpl() : false;
  }

  inline bool IsWriteable(void) const {
    return impl ? IsWriteableImpl() : false;
  }

  inline bool IsExecutable(void) const {
    return impl ? IsExecutableImpl() : false;
  }

  inline bool IsStack(void) const {
    return impl ? IsStackImpl() : false;
  }

  inline bool IsUndefined(void) const {
    return impl ? IsUndefinedImpl() : true;
  }

  inline bool SetUndefined(bool is_undef=true) const {
    if (impl) {
      return SetUndefinedImpl(is_undef);
    } else {
      return false;
    }
  }

  inline llvm::Expected<uint8_t> Value(void) const {
    if (impl) {
      return ValueImpl();
    } else {
      return llvm::createStringError(
          std::make_error_code(std::errc::bad_address),
          "Cannot read value of invalid byte at address '%lx'",
          addr);
    }
  }

 private:
  friend class Program;

  bool IsReadableImpl(void) const;
  bool IsWriteableImpl(void) const;
  bool IsExecutableImpl(void) const;
  bool IsStackImpl(void) const;

  bool IsUndefinedImpl(void) const;
  bool SetUndefinedImpl(bool is_undef) const;
  uint8_t ValueImpl(void) const;

  explicit inline Byte(uint64_t addr_, Impl *impl_)
      : addr(addr_),
        impl(impl_) {}

  uint64_t addr{0};
  Impl *impl{nullptr};
};

struct FunctionDecl;
struct GlobalVarDecl;

// A view into a program binary and its data.
//
// NOTE(pag): A variable and a function can be co-located,
//            but two variables cannot share the same address,
//            nor can two functions share the same address.
//
// NOTE(pag): Multiple functions/variables can share the same
//            name. This is common in the core dump / snapshot
//            scenario. For example, an ELF relocatable binary
//            will have a GOT/PLT entry thunk/stub for an external
//            function, and this stub will share the same name
//            as the intended target, which would could be a
//            function defined in a shared library, also present
//            in the address space.
class Program {
 public:
  Program(void);

  ~Program(void);
  Program(const Program &) = default;
  Program &operator=(const Program &) = default;

  // Returns the initial stack pointer for functions to use.
  llvm::Expected<uint64_t> InitialStackPointer(void) const;

  // Map a range of bytes into the program.
  //
  // This expects that none of the bytes already in that range
  // are mapped. There are no requirements on the alignment
  // of the mapped bytes.
  llvm::Error MapRange(const ByteRange &range);

  // Map a custom stack range.
  llvm::Error MapStack(uint64_t base_address, uint64_t limit_address,
                       uint64_t start_address);

  // Declare a function in this view. This takes in a function
  // declaration that will act as a sort of "template" for the
  // declaration that we will make and will be owned by `Program`.
  //
  // What is expected of a declaration template:
  //    - `arch` is non-nullptr.
  //    - `address` is unique across all functions, and can be
  //      represented as a 48 bit signed integer.
  //    - `type` is nullptr. This function will create the
  //      appropriate LLVM type given the types in `params` and
  //      `returns`. This implies those values must have correct
  //      LLVM types.
  //    - `name` is optional, and if empty, will be initialized
  //      according to the `sub_xxx` convention.
  //    - All other fields be filled out.
  //
  // This function will check for error conditions and report them
  // as appropriate.
  llvm::Error DeclareFunction(
      const FunctionDecl &decl_template) const;

  // Internal iterator over all functions.
  //
  // NOTE(pag): New functions *can* be declared while this method
  //            is actively iterating.
  void ForEachFunction(
      std::function<bool(const FunctionDecl *)> callback) const;

  // Search for a specific function by its address.
  const FunctionDecl *FindFunction(uint64_t address) const;

  // Call `callback` on each function with the given name.
  //
  // NOTE(pag): The same function may be revisited if a function
  //            is added within the dynamic scope of `callback`s
  //            execution.
  void ForEachFunctionWithName(
      const std::string &name,
      std::function<bool(const FunctionDecl *)> callback) const;

  // Declare a variable in this view. This takes in a variable
  // declaration that will act as a sort of "template" for the
  // declaration that we will make and will be owned by `Program`.
  //
  // What is expected of a declaration template:
  //    - `arch` is non-nullptr.
  //    - `address` is unique across all variables, and can be
  //      represented as a 48 bit signed integer.
  //    - `type` is non-nullptr.
  //    - `name` is optional, and if empty, will be initialized
  //      according to the `data_xxx` convention.
  //
  // This function will check for error conditions and report them
  // as appropriate.
  llvm::Error DeclareVariable(
      const GlobalVarDecl &decl_template) const;

  // Internal iterator over all vars.
  //
  // NOTE(pag): New variables *can* be declared while this method
  //            is actively iterating.
  void ForEachVariable(
      std::function<bool(const GlobalVarDecl *)> callback) const;

  // Search for a specific variable by its address.
  const GlobalVarDecl *FindVariable(uint64_t address) const;

  // Call `callback` on each variable with the given name.
  //
  // NOTE(pag): The same variable may be revisited if a function
  //            is added within the dynamic scope of `callback`s
  //            execution.
  void ForEachVariableWithName(
      const std::string &name,
      std::function<bool(const GlobalVarDecl *)> callback) const;

  // Access memory, looking for a specific byte. Returns
  // the byte found, if any.
  Byte FindByte(uint64_t address) const;

  class Impl;

 private:
  Program(Program &&) noexcept = delete;
  Program &operator=(Program &&) noexcept = delete;

  std::shared_ptr<Impl> impl;
};

}  // namespace anvill
