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

#include <remill/BC/Compat/Error.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>

#include <anvill/Providers/ControlFlowProvider.h>

// Forward declare
namespace llvm {
class Type;
class DataLayout;
}  // namespace llvm

namespace anvill {

// Represents a range of bytes, whose data is found in the range
// `[begin, end)`.
struct ByteRange {
  uint64_t address{0};
  const uint8_t *begin{nullptr};
  const uint8_t *end{nullptr};  // Exclusive.
  bool is_writeable{false};
  bool is_executable{false};
};

class Program;
struct ByteSequence;

// Abstraction around a byte, its location, and metadata
// associated with it.
struct Byte {
 public:
  using Data = uint8_t;
  struct Meta;

  ~Byte(void) = default;
  Byte(void) = default;
  Byte(const Byte &) = default;
  Byte(Byte &&) noexcept = default;
  Byte &operator=(const Byte &) = default;
  Byte &operator=(Byte &&) noexcept = default;

  inline operator bool(void) const {
    return data != nullptr;
  }

  inline uint64_t Address(void) const {
    return addr;
  }

  inline bool IsWriteable(void) const {
    return data ? IsWriteableImpl() : false;
  }

  inline bool IsExecutable(void) const {
    return data ? IsExecutableImpl() : false;
  }

  inline bool IsUndefined(void) const {
    return data ? IsUndefinedImpl() : true;
  }

  inline bool SetUndefined(bool is_undef = true) const {
    if (data) {
      return SetUndefinedImpl(is_undef);
    } else {
      return false;
    }
  }

  inline llvm::Expected<uint8_t> Value(void) const {
    if (data) {
      return *data;
    } else {
      return llvm::createStringError(
          std::make_error_code(std::errc::bad_address),
          "Cannot read value of invalid byte at address '%lx'", addr);
    }
  }

  inline uint8_t ValueOr(uint8_t backup) const {
    return data ? *data : backup;
  }

 private:
  friend class Program;
  friend struct ByteSequence;

  bool IsWriteableImpl(void) const;
  bool IsExecutableImpl(void) const;

  bool IsUndefinedImpl(void) const;
  bool SetUndefinedImpl(bool is_undef) const;

  explicit inline Byte(uint64_t addr_, Data *data_, Meta *meta_)
      : addr(addr_),
        data(data_),
        meta(meta_) {}

  uint64_t addr{0};
  Data *data{nullptr};
  Meta *meta{nullptr};
};

// Abstraction around a byte sequence.
struct ByteSequence {
 public:
  inline operator bool(void) const {
    return first_data != nullptr;
  }

  inline size_t Size(void) const {
    return size;
  }

  inline uint64_t Address(void) const {
    return address;
  }

  // Convert this byte sequence to a string.
  std::string_view ToString(void) const;

  // Extract a substring of bytes from this byte sequence.
  std::string_view Substring(uint64_t ea, size_t seq_size) const;

  // Index a specific byte within this sequence. Indexing is based off of the
  // byte's address.
  Byte operator[](uint64_t ea) const;

 private:
  friend class Program;

  explicit inline ByteSequence(uint64_t addr_, Byte::Data *first_data_,
                               Byte::Meta *first_meta_, size_t size_)
      : address(addr_),
        first_data(first_data_),
        first_meta(first_meta_),
        size(size_) {}

  uint64_t address{0};
  Byte::Data *first_data{nullptr};
  Byte::Meta *first_meta{nullptr};  // Inclusive.
  size_t size{0};
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
  Program(Program &&) noexcept = default;
  Program &operator=(const Program &) = default;
  Program &operator=(Program &&) noexcept = default;

  // Map a range of bytes into the program.
  //
  // This expects that none of the bytes already in that range
  // are mapped. There are no requirements on the alignment
  // of the mapped bytes.
  llvm::Error MapRange(const ByteRange &range);

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
  llvm::Expected<FunctionDecl *>
  DeclareFunction(const FunctionDecl &decl_template, bool force = false) const;

  // Internal iterator over all functions.
  //
  // NOTE(pag): New functions *can* be declared while this method
  //            is actively iterating.
  void
  ForEachFunction(std::function<bool(const FunctionDecl *)> callback) const;

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

  // Returns a possible control flow redirection for the given address
  // or the input address itself if nothing is found
  bool TryGetControlFlowRedirection(std::uint64_t &destination,
                                    std::uint64_t address) const;

  // Adds a new control flow redirection entry
  void AddControlFlowRedirection(std::uint64_t from, std::uint64_t to);

  // Returns a list of targets reachable from the given address
  std::optional<ControlFlowTargetList>
  TryGetControlFlowTargets(std::uint64_t address) const;

  // Sets a list of targets reachable from the given address; fails if the
  // specified source address already has an existing target list
  bool TrySetControlFlowTargets(const ControlFlowTargetList &target_list);

  // Add a name to an address.
  void AddNameToAddress(const std::string &name, uint64_t address) const;

  // Apply a function `cb` to each name of the address `address`.
  void ForEachNameOfAddress(
      uint64_t address,
      std::function<bool(const std::string &, const FunctionDecl *,
                         const GlobalVarDecl *)>
          cb) const;

  // Apply a function `cb` to each address of the named symbol `name`.
  void ForEachAddressOfName(
      const std::string &name,
      std::function<bool(uint64_t, const FunctionDecl *, const GlobalVarDecl *)>
          cb) const;

  // Apply a function `cb` to each address/name pair.
  void ForEachNamedAddress(
      std::function<bool(uint64_t, const std::string &, const FunctionDecl *,
                         const GlobalVarDecl *)>
          cb) const;

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
  llvm::Error DeclareVariable(const GlobalVarDecl &decl_template) const;

  // Internal iterator over all vars.
  //
  // NOTE(pag): New variables *can* be declared while this method
  //            is actively iterating.
  void
  ForEachVariable(std::function<bool(const GlobalVarDecl *)> callback) const;

  // Search for a specific variable by its address.
  const GlobalVarDecl *FindVariable(uint64_t address) const;

  // Determine if an address lies somewhere within a known variable
  const GlobalVarDecl *FindInVariable(uint64_t address,
                                      const llvm::DataLayout &layout) const;

  // Call `callback` on each variable with the given name.
  //
  // NOTE(pag): The same variable may be revisited if a function
  //            is added within the dynamic scope of `callback`s
  //            execution.
  void ForEachVariableWithName(
      const std::string &name,
      std::function<bool(const GlobalVarDecl *)> callback) const;

  // Access memory, looking for a specific byte. Returns the byte found, if any.
  Byte FindByte(uint64_t address) const;


  // Find which byte sequence (defined in the spec) has the provided `address`
  ByteSequence FindBytesContaining(uint64_t address) const;

  // Find the next byte.
  Byte FindNextByte(Byte byte) const;

  // Find a sequence of bytes within the same mapped range starting at
  // `address` and including as many bytes fall within the range up to
  // but not including `address+size`.
  ByteSequence FindBytes(uint64_t address, size_t size) const;

  class Impl;

 private:
  explicit Program(void *opaque);

  std::shared_ptr<Impl> impl;
};

}  // namespace anvill
