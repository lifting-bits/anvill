# Copyright (c) 2019 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


class Arch(object):
  """Generic architecture description."""

  def name(self):
    raise NotImplementedError()

  def program_counter_name(self):
    raise NotImplementedError()

  def stack_pointer_name(self):
    raise NotImplementedError()

  def return_address_proto(self):
    raise NotImplementedError()

  def return_stack_pointer_proto(self, num_bytes_popped):
    raise NotImplementedError()

  def pointer_size(self):
    raise NotImplementedError()


class AMD64Arch(Arch):
  """AMD64-specific architecture description (64-bit)."""

  def name(self):
    return "amd64"

  def program_counter_name(self):
    return "RIP"

  def stack_pointer_name(self):
    return "RSP"

  def return_address_proto(self):
    return {
      "memory": {
        "register": "RSP",
        "offset": 0
      },
      "type": "L"
    }

  def return_stack_pointer_proto(self, num_bytes_popped):
    return {
      "register": "RSP",
      "offset": abs(num_bytes_popped) + 8
    }

  def pointer_size(self):
    raise 8


class X86Arch(Arch):
  """X86-specific architecture description (32-bit)."""

  def name(self):
    return "x86"

  def program_counter_name(self):
    return "EIP"

  def stack_pointer_name(self):
    return "ESP"

  def return_address_proto(self):
    return {
      "memory": {
        "register": "ESP",
        "offset": 0
      },
      "type": "I"
    }

  def return_stack_pointer_proto(self, num_bytes_popped):
    return {
      "register": "ESP",
      "offset": abs(num_bytes_popped) + 4
    }

  def pointer_size(self):
    raise 4


class AArch64Arch(Arch):
  """AArch64-specific architecture description (ARMv8, 64-bit)."""

  def name(self):
    return "aarch64"

  def program_counter_name(self):
    return "PC"

  def stack_pointer_name(self):
    return "SP"

  def return_address_proto(self):
    return {
      "register": "X0",
      "type": "L"
    }

  def return_stack_pointer_proto(self, num_bytes_popped):
    return {
      "register": "SP",
      "offset": abs(num_bytes_popped)
    }

  def pointer_size(self):
    raise 8

