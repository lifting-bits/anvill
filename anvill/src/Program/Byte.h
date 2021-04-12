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

#include <cstdint>

#include <llvm/Support/Error.h>

namespace anvill {

// Abstraction around a byte, its location, and metadata
// associated with it.
class Byte final {
  public:

  // A byte's associated metadata. The metadata is updated throughout the
  // lifting/decompiling process.
  struct Meta {
    // True if there is a subsequent byte in the range that can be accessed.
    bool next_byte_is_in_range : 1;

    // True if there is a subsequent byte
    bool next_byte_starts_new_range : 1;

    // Is the value of this byte undefined? Our model of the stack
    // begins with all stack bytes, unless explicitly specified, as
    // undefined.
    bool is_undefined : 1;

    // Is this byte the beginning of a variable?
    bool is_variable_head : 1;

    // These require `is_executable` to be `true`.
    bool is_function_head : 1;

    // If `false`, then the implied semantic is that the byte will *never* be
    // writable. For example, if we're decompiling a snapshot or a core dump,
    // then the data associated with the ELF GOT/PLT sections would likely we
    // treated as being "constant" so that we could read through them.
    //
    // NOTE(pag): For jump tables to work most effectively, we expect the bytes
    //            that store the offsets/displacements/etc. to be marked as
    //            constants.
    bool is_writeable : 1;

    // NOTE(pag): We *only* treat a byte as possibly belonging to an instruction
    //            if `is_writable` is false. The semantic here is that we're
    //            unprepared to handle self-modifying code. Further, we don't
    //            want to treat bytes that might be in executable stacks as being
    //            code.
    bool is_executable : 1;

    // Do we have extended meta-data attached to this byte? This might include
    // things like devirtualization targets for calls through thunks or jump
    // tables.
    bool has_extended_meta : 1;

  } __attribute__((packed));

  using Data = std::uint8_t;

  static_assert(sizeof(Byte::Data) == sizeof(uint8_t),
                "Invalid packing of `struct Byte::Data`.");

  static_assert(sizeof(Byte::Meta) == sizeof(uint8_t),
                "Invalid packing of `struct Byte::Meta`.");

  Byte();
  Byte(uint64_t addr_, Data *data_, Meta *meta_);
  ~Byte(void);

  operator bool(void) const;
  uint64_t Address(void) const;

  bool IsWriteable(void) const;
  bool IsExecutable(void) const;
  bool IsUndefined(void) const;
  bool SetUndefined(bool is_undef = true);
  llvm::Expected<uint8_t> Value(void) const;
  inline uint8_t ValueOr(uint8_t backup) const;

  Byte(const Byte &) = default;
  Byte(Byte &&) noexcept = default;

  Byte &operator=(const Byte &) = default;
  Byte &operator=(Byte &&) noexcept = default;

  uint64_t addr{0U};
  Data *data{nullptr};
  Meta *meta{nullptr};
};

}
