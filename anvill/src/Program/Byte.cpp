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

#include "Byte.h"

#include <system_error>

namespace anvill {

Byte::Byte() : addr(0U), data(nullptr), meta(nullptr) {}

Byte::Byte(uint64_t addr_, Byte::Data *data_, Byte::Meta *meta_) : addr(addr_), data(data_), meta(meta_) {}

Byte::~Byte(void) = default;

Byte::operator bool(void) const {
  return data != nullptr;
}

uint64_t Byte::Address(void) const {
  return addr;
}

bool Byte::IsWriteable(void) const {
  if (data == nullptr) {
    return false;
  }

  return meta->is_writeable;
}

bool Byte::IsExecutable(void) const {
  if (data == nullptr) {
    return false;
  }
  
  return meta->is_executable;
}

bool Byte::IsUndefined(void) const {
  if (data == nullptr) {
    return true;
  }

  return meta->is_undefined;
}

bool Byte::SetUndefined(bool is_undef) {
  if (meta->is_function_head && !meta->is_variable_head) {
    meta->is_undefined = is_undef;
    return true;
  } else {
    return false;
  }
}

llvm::Expected<uint8_t> Byte::Value(void) const {
    if (data) {
      return *data;
    } else {
      return llvm::createStringError(
          std::make_error_code(std::errc::bad_address),
          "Cannot read value of invalid byte at address '%lx'", addr);
    }
}

uint8_t Byte::ValueOr(uint8_t backup) const {
    return data ? *data : backup;
}

}
