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

#include <cstdint>
#include <memory>

namespace llvm {
class GlobalAlias;
}  // namespace llvm
namespace anvill {

class DataLifterImpl;

class DataLifter {
 public:
  ~DataLifter(void);


  DataLifter(const DataLifter &) = default;
  DataLifter(DataLifter &&) noexcept = default;
  DataLifter &operator=(const DataLifter &) = default;
  DataLifter &operator=(DataLifter &&) noexcept = default;

 private:
  std::shared_ptr<DataLifterImpl> impl;
};

}  // namespace anvill
