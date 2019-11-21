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

  def register_family(self, reg_name):
    raise NotImplementedError()


class AMD64Arch(Arch):
  """AMD64-specific architecture description (64-bit)."""

  _REG_FAMILY_rX = lambda l: (
    ("R{}X".format(l), 0, 8),
    ("E{}X".format(l), 0, 4),
    ("{}X".format(l), 0, 2),
    ("{}H".format(l), 1, 1),
    ("{}L".format(l), 0, 1),
  )

  _REG_FAMILY_AX = _REG_FAMILY_rX("A")
  _REG_FAMILY_BX = _REG_FAMILY_rX("B")
  _REG_FAMILY_CX = _REG_FAMILY_rX("C")
  _REG_FAMILY_DX = _REG_FAMILY_rX("D")

  _REG_FAMILY_rI = lambda l: (
    ("R{}".format(l), 0, 8),
    ("E{}".format(l), 0, 4),
    ("{}".format(l), 0, 2),
    ("{}L".format(l), 0, 1),
  )

  _REG_FAMILY_SI = _REG_FAMILY_rI("SI")
  _REG_FAMILY_DI = _REG_FAMILY_rI("DI")
  _REG_FAMILY_SP = _REG_FAMILY_rI("SP")
  _REG_FAMILY_BP = _REG_FAMILY_rI("BP")
  _REG_FAMILY_IP = _REG_FAMILY_rI("IP")  # NOTE: no `IPL`, oh well.

  _REG_FAMILY_rN = lambda l: (
    ("R{}".format(l), 0, 8),
    ("R{}D".format(l), 0, 4),
    ("R{}W".format(l), 0, 2),
    ("R{}B".format(l), 0, 1),
  )

  _REG_FAMILY_R8 = _REG_FAMILY_rN(8)
  _REG_FAMILY_R9 = _REG_FAMILY_rN(9)
  _REG_FAMILY_R10 = _REG_FAMILY_rN(10)
  _REG_FAMILY_R11 = _REG_FAMILY_rN(11)
  _REG_FAMILY_R12 = _REG_FAMILY_rN(12)
  _REG_FAMILY_R13 = _REG_FAMILY_rN(13)
  _REG_FAMILY_R14 = _REG_FAMILY_rN(14)
  _REG_FAMILY_R15 = _REG_FAMILY_rN(15)

  _REG_FAMILY_xN = lambda l: (
    ("ZMM{}".format(l), 0, 64),
    ("YMM{}".format(l), 0, 32),
    ("XMM{}".format(l), 0, 16),
  )

  _REG_FAMILY_XMM0 = _REG_FAMILY_xN(0)
  _REG_FAMILY_XMM1 = _REG_FAMILY_xN(1)
  _REG_FAMILY_XMM2 = _REG_FAMILY_xN(2)
  _REG_FAMILY_XMM3 = _REG_FAMILY_xN(3)
  _REG_FAMILY_XMM4 = _REG_FAMILY_xN(4)
  _REG_FAMILY_XMM5 = _REG_FAMILY_xN(5)
  _REG_FAMILY_XMM6 = _REG_FAMILY_xN(6)
  _REG_FAMILY_XMM7 = _REG_FAMILY_xN(7)
  _REG_FAMILY_XMM8 = _REG_FAMILY_xN(8)
  _REG_FAMILY_XMM9 = _REG_FAMILY_xN(9)

  _REG_FAMILY_XMM10 = _REG_FAMILY_xN(10)
  _REG_FAMILY_XMM11 = _REG_FAMILY_xN(11)
  _REG_FAMILY_XMM12 = _REG_FAMILY_xN(12)
  _REG_FAMILY_XMM13 = _REG_FAMILY_xN(13)
  _REG_FAMILY_XMM14 = _REG_FAMILY_xN(14)
  _REG_FAMILY_XMM15 = _REG_FAMILY_xN(15)
  _REG_FAMILY_XMM16 = _REG_FAMILY_xN(16)
  _REG_FAMILY_XMM17 = _REG_FAMILY_xN(17)
  _REG_FAMILY_XMM18 = _REG_FAMILY_xN(18)
  _REG_FAMILY_XMM19 = _REG_FAMILY_xN(19)

  _REG_FAMILY_XMM20 = _REG_FAMILY_xN(20)
  _REG_FAMILY_XMM21 = _REG_FAMILY_xN(21)
  _REG_FAMILY_XMM22 = _REG_FAMILY_xN(22)
  _REG_FAMILY_XMM23 = _REG_FAMILY_xN(23)
  _REG_FAMILY_XMM24 = _REG_FAMILY_xN(24)
  _REG_FAMILY_XMM25 = _REG_FAMILY_xN(25)
  _REG_FAMILY_XMM26 = _REG_FAMILY_xN(26)
  _REG_FAMILY_XMM27 = _REG_FAMILY_xN(27)
  _REG_FAMILY_XMM28 = _REG_FAMILY_xN(28)
  _REG_FAMILY_XMM29 = _REG_FAMILY_xN(29)

  _REG_FAMILY_XMM30 = _REG_FAMILY_xN(30)
  _REG_FAMILY_XMM31 = _REG_FAMILY_xN(31)

  _REG_FAMILY = {
    "AL":   _REG_FAMILY_AX,
    "AH":   _REG_FAMILY_AX,
    "AX":   _REG_FAMILY_AX,
    "EAX":  _REG_FAMILY_AX,
    "RAX":  _REG_FAMILY_AX,
    "BL":   _REG_FAMILY_BX,
    "BH":   _REG_FAMILY_BX,
    "BX":   _REG_FAMILY_BX,
    "EBX":  _REG_FAMILY_BX,
    "RBX":  _REG_FAMILY_BX,
    "CL":   _REG_FAMILY_CX,
    "CH":   _REG_FAMILY_CX,
    "CX":   _REG_FAMILY_CX,
    "ECX":  _REG_FAMILY_CX,
    "RCX":  _REG_FAMILY_CX,
    "DL":   _REG_FAMILY_DX,
    "DH":   _REG_FAMILY_DX,
    "DX":   _REG_FAMILY_DX,
    "EDX":  _REG_FAMILY_DX,
    "RDX":  _REG_FAMILY_DX,
    "SIL":  _REG_FAMILY_SI,
    "SI":   _REG_FAMILY_SI,
    "ESI":  _REG_FAMILY_SI,
    "RSI":  _REG_FAMILY_SI,
    "DIL":  _REG_FAMILY_DI,
    "DI":   _REG_FAMILY_DI,
    "EDI":  _REG_FAMILY_DI,
    "RDI":  _REG_FAMILY_DI,
    "SPL":  _REG_FAMILY_SP,
    "SP":   _REG_FAMILY_SP,
    "ESP":  _REG_FAMILY_SP,
    "RSP":  _REG_FAMILY_SP,
    "BPL":  _REG_FAMILY_BP,
    "BP":   _REG_FAMILY_BP,
    "EBP":  _REG_FAMILY_BP,
    "RBP":  _REG_FAMILY_BP,
    "IP":   _REG_FAMILY_IP,
    "EIP":  _REG_FAMILY_IP,
    "RIP":  _REG_FAMILY_IP,
    "R8B":  _REG_FAMILY_R8,
    "R8W":  _REG_FAMILY_R8,
    "R8D":  _REG_FAMILY_R8,
    "R8":   _REG_FAMILY_R8,
    "R9B":  _REG_FAMILY_R9,
    "R9W":  _REG_FAMILY_R9,
    "R9D":  _REG_FAMILY_R9,
    "R9":   _REG_FAMILY_R9,
    "R10B": _REG_FAMILY_R10,
    "R10W": _REG_FAMILY_R10,
    "R10D": _REG_FAMILY_R10,
    "R10":  _REG_FAMILY_R10,
    "R11B": _REG_FAMILY_R11,
    "R11W": _REG_FAMILY_R11,
    "R11D": _REG_FAMILY_R11,
    "R11":  _REG_FAMILY_R11,
    "R12B": _REG_FAMILY_R12,
    "R12W": _REG_FAMILY_R12,
    "R12D": _REG_FAMILY_R12,
    "R12":  _REG_FAMILY_R12,
    "R13B": _REG_FAMILY_R13,
    "R13W": _REG_FAMILY_R13,
    "R13D": _REG_FAMILY_R13,
    "R13":  _REG_FAMILY_R13,
    "R14B": _REG_FAMILY_R14,
    "R14W": _REG_FAMILY_R14,
    "R14D": _REG_FAMILY_R14,
    "R14":  _REG_FAMILY_R14,
    "R15B": _REG_FAMILY_R15,
    "R15W": _REG_FAMILY_R15,
    "R15D": _REG_FAMILY_R15,
    "R15":  _REG_FAMILY_R15,
    "XMM0": _REG_FAMILY_XMM0,
    "YMM0": _REG_FAMILY_XMM0,
    "ZMM0": _REG_FAMILY_XMM0,
    "XMM1": _REG_FAMILY_XMM1,
    "YMM1": _REG_FAMILY_XMM1,
    "ZMM1": _REG_FAMILY_XMM1,
    "XMM2": _REG_FAMILY_XMM2,
    "YMM2": _REG_FAMILY_XMM2,
    "ZMM2": _REG_FAMILY_XMM2,
    "XMM3": _REG_FAMILY_XMM3,
    "YMM3": _REG_FAMILY_XMM3,
    "ZMM3": _REG_FAMILY_XMM3,
    "XMM4": _REG_FAMILY_XMM4,
    "YMM4": _REG_FAMILY_XMM4,
    "ZMM4": _REG_FAMILY_XMM4,
    "XMM5": _REG_FAMILY_XMM5,
    "YMM5": _REG_FAMILY_XMM5,
    "ZMM5": _REG_FAMILY_XMM5,
    "XMM6": _REG_FAMILY_XMM6,
    "YMM6": _REG_FAMILY_XMM6,
    "ZMM6": _REG_FAMILY_XMM6,
    "XMM7": _REG_FAMILY_XMM7,
    "YMM7": _REG_FAMILY_XMM7,
    "ZMM7": _REG_FAMILY_XMM7,
    "XMM8": _REG_FAMILY_XMM8,
    "YMM8": _REG_FAMILY_XMM8,
    "ZMM8": _REG_FAMILY_XMM8,
    "XMM9": _REG_FAMILY_XMM9,
    "YMM9": _REG_FAMILY_XMM9,
    "ZMM9": _REG_FAMILY_XMM9,

    "XMM10": _REG_FAMILY_XMM10,
    "YMM10": _REG_FAMILY_XMM10,
    "ZMM10": _REG_FAMILY_XMM10,
    "XMM11": _REG_FAMILY_XMM11,
    "YMM11": _REG_FAMILY_XMM11,
    "ZMM11": _REG_FAMILY_XMM11,
    "XMM12": _REG_FAMILY_XMM12,
    "YMM12": _REG_FAMILY_XMM12,
    "ZMM12": _REG_FAMILY_XMM12,
    "XMM13": _REG_FAMILY_XMM13,
    "YMM13": _REG_FAMILY_XMM13,
    "ZMM13": _REG_FAMILY_XMM13,
    "XMM14": _REG_FAMILY_XMM14,
    "YMM14": _REG_FAMILY_XMM14,
    "ZMM14": _REG_FAMILY_XMM14,
    "XMM15": _REG_FAMILY_XMM15,
    "YMM15": _REG_FAMILY_XMM15,
    "ZMM15": _REG_FAMILY_XMM15,
    "XMM16": _REG_FAMILY_XMM16,
    "YMM16": _REG_FAMILY_XMM16,
    "ZMM16": _REG_FAMILY_XMM16,
    "XMM17": _REG_FAMILY_XMM17,
    "YMM17": _REG_FAMILY_XMM17,
    "ZMM17": _REG_FAMILY_XMM17,
    "XMM18": _REG_FAMILY_XMM18,
    "YMM18": _REG_FAMILY_XMM18,
    "ZMM18": _REG_FAMILY_XMM18,
    "XMM19": _REG_FAMILY_XMM19,
    "YMM19": _REG_FAMILY_XMM19,
    "ZMM19": _REG_FAMILY_XMM19,

    "XMM20": _REG_FAMILY_XMM20,
    "YMM20": _REG_FAMILY_XMM20,
    "ZMM20": _REG_FAMILY_XMM20,
    "XMM21": _REG_FAMILY_XMM21,
    "YMM21": _REG_FAMILY_XMM21,
    "ZMM21": _REG_FAMILY_XMM21,
    "XMM22": _REG_FAMILY_XMM22,
    "YMM22": _REG_FAMILY_XMM22,
    "ZMM22": _REG_FAMILY_XMM22,
    "XMM23": _REG_FAMILY_XMM23,
    "YMM23": _REG_FAMILY_XMM23,
    "ZMM23": _REG_FAMILY_XMM23,
    "XMM24": _REG_FAMILY_XMM24,
    "YMM24": _REG_FAMILY_XMM24,
    "ZMM24": _REG_FAMILY_XMM24,
    "XMM25": _REG_FAMILY_XMM25,
    "YMM25": _REG_FAMILY_XMM25,
    "ZMM25": _REG_FAMILY_XMM25,
    "XMM26": _REG_FAMILY_XMM26,
    "YMM26": _REG_FAMILY_XMM26,
    "ZMM26": _REG_FAMILY_XMM26,
    "XMM27": _REG_FAMILY_XMM27,
    "YMM27": _REG_FAMILY_XMM27,
    "ZMM27": _REG_FAMILY_XMM27,
    "XMM28": _REG_FAMILY_XMM28,
    "YMM28": _REG_FAMILY_XMM28,
    "ZMM28": _REG_FAMILY_XMM28,
    "XMM29": _REG_FAMILY_XMM29,
    "YMM29": _REG_FAMILY_XMM29,
    "ZMM29": _REG_FAMILY_XMM29,

    "XMM30": _REG_FAMILY_XMM30,
    "YMM30": _REG_FAMILY_XMM30,
    "ZMM30": _REG_FAMILY_XMM30,
    "XMM31": _REG_FAMILY_XMM31,
    "YMM31": _REG_FAMILY_XMM31,
    "ZMM31": _REG_FAMILY_XMM31,

    "MM0": (("MM0", 0, 8),),
    "MM1": (("MM1", 0, 8),),
    "MM2": (("MM2", 0, 8),),
    "MM3": (("MM3", 0, 8),),
    "MM4": (("MM4", 0, 8),),
    "MM5": (("MM5", 0, 8),),
    "MM6": (("MM6", 0, 8),),
    "MM7": (("MM7", 0, 8),),

    "ST0": (("ST0", 0, 10), ("ST0", 0, 12), ("ST0", 0, 16)),
    "ST1": (("ST1", 0, 10), ("ST1", 0, 12), ("ST1", 0, 16)),
    "ST2": (("ST2", 0, 10), ("ST2", 0, 12), ("ST2", 0, 16)),
    "ST3": (("ST3", 0, 10), ("ST3", 0, 12), ("ST3", 0, 16)),
    "ST4": (("ST4", 0, 10), ("ST4", 0, 12), ("ST4", 0, 16)),
    "ST5": (("ST5", 0, 10), ("ST5", 0, 12), ("ST5", 0, 16)),
    "ST6": (("ST6", 0, 10), ("ST6", 0, 12), ("ST6", 0, 16)),
    "ST7": (("ST7", 0, 10), ("ST7", 0, 12), ("ST7", 0, 16)),
  }

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
      "offset": abs(num_bytes_popped) + 8,
      "type": "L"
    }

  def pointer_size(self):
    return 8

  def register_family(self, reg_name):
    return self._REG_FAMILY[reg_name]


class X86Arch(Arch):
  """X86-specific architecture description (32-bit)."""

  _REG_FAMILY_rX = lambda l: (
    ("E{}X".format(l), 0, 4),
    ("{}X".format(l), 0, 2),
    ("{}H".format(l), 1, 1),
    ("{}L".format(l), 0, 1),
  )

  _REG_FAMILY_AX = _REG_FAMILY_rX("A")
  _REG_FAMILY_BX = _REG_FAMILY_rX("B")
  _REG_FAMILY_CX = _REG_FAMILY_rX("C")
  _REG_FAMILY_DX = _REG_FAMILY_rX("D")

  _REG_FAMILY_rI = lambda l: (
    ("E{}".format(l), 0, 4),
    ("{}".format(l), 0, 2),
    ("{}L".format(l), 0, 1),
  )

  _REG_FAMILY_SI = _REG_FAMILY_rI("SI")
  _REG_FAMILY_DI = _REG_FAMILY_rI("DI")
  _REG_FAMILY_SP = _REG_FAMILY_rI("SP")
  _REG_FAMILY_BP = _REG_FAMILY_rI("BP")
  _REG_FAMILY_IP = _REG_FAMILY_rI("IP")  # NOTE: no `IPL`, oh well.

  _REG_FAMILY_xN = lambda l: (
    ("ZMM{}".format(l), 0, 64),
    ("YMM{}".format(l), 0, 32),
    ("XMM{}".format(l), 0, 16),
  )

  _REG_FAMILY_XMM0 = _REG_FAMILY_xN(0)
  _REG_FAMILY_XMM1 = _REG_FAMILY_xN(1)
  _REG_FAMILY_XMM2 = _REG_FAMILY_xN(2)
  _REG_FAMILY_XMM3 = _REG_FAMILY_xN(3)
  _REG_FAMILY_XMM4 = _REG_FAMILY_xN(4)
  _REG_FAMILY_XMM5 = _REG_FAMILY_xN(5)
  _REG_FAMILY_XMM6 = _REG_FAMILY_xN(6)
  _REG_FAMILY_XMM7 = _REG_FAMILY_xN(7)
  _REG_FAMILY_XMM8 = _REG_FAMILY_xN(8)
  _REG_FAMILY_XMM9 = _REG_FAMILY_xN(9)

  _REG_FAMILY_XMM10 = _REG_FAMILY_xN(10)
  _REG_FAMILY_XMM11 = _REG_FAMILY_xN(11)
  _REG_FAMILY_XMM12 = _REG_FAMILY_xN(12)
  _REG_FAMILY_XMM13 = _REG_FAMILY_xN(13)
  _REG_FAMILY_XMM14 = _REG_FAMILY_xN(14)
  _REG_FAMILY_XMM15 = _REG_FAMILY_xN(15)
  _REG_FAMILY_XMM16 = _REG_FAMILY_xN(16)
  _REG_FAMILY_XMM17 = _REG_FAMILY_xN(17)
  _REG_FAMILY_XMM18 = _REG_FAMILY_xN(18)
  _REG_FAMILY_XMM19 = _REG_FAMILY_xN(19)

  _REG_FAMILY_XMM20 = _REG_FAMILY_xN(20)
  _REG_FAMILY_XMM21 = _REG_FAMILY_xN(21)
  _REG_FAMILY_XMM22 = _REG_FAMILY_xN(22)
  _REG_FAMILY_XMM23 = _REG_FAMILY_xN(23)
  _REG_FAMILY_XMM24 = _REG_FAMILY_xN(24)
  _REG_FAMILY_XMM25 = _REG_FAMILY_xN(25)
  _REG_FAMILY_XMM26 = _REG_FAMILY_xN(26)
  _REG_FAMILY_XMM27 = _REG_FAMILY_xN(27)
  _REG_FAMILY_XMM28 = _REG_FAMILY_xN(28)
  _REG_FAMILY_XMM29 = _REG_FAMILY_xN(29)

  _REG_FAMILY_XMM30 = _REG_FAMILY_xN(30)
  _REG_FAMILY_XMM31 = _REG_FAMILY_xN(31)

  _REG_FAMILY = {
    "AL":   _REG_FAMILY_AX,
    "AH":   _REG_FAMILY_AX,
    "AX":   _REG_FAMILY_AX,
    "EAX":  _REG_FAMILY_AX,
    "BL":   _REG_FAMILY_BX,
    "BH":   _REG_FAMILY_BX,
    "BX":   _REG_FAMILY_BX,
    "EBX":  _REG_FAMILY_BX,
    "CL":   _REG_FAMILY_CX,
    "CH":   _REG_FAMILY_CX,
    "CX":   _REG_FAMILY_CX,
    "ECX":  _REG_FAMILY_CX,
    "DL":   _REG_FAMILY_DX,
    "DH":   _REG_FAMILY_DX,
    "DX":   _REG_FAMILY_DX,
    "EDX":  _REG_FAMILY_DX,
    "SIL":  _REG_FAMILY_SI,
    "SI":   _REG_FAMILY_SI,
    "ESI":  _REG_FAMILY_SI,
    "DIL":  _REG_FAMILY_DI,
    "DI":   _REG_FAMILY_DI,
    "EDI":  _REG_FAMILY_DI,
    "SPL":  _REG_FAMILY_SP,
    "SP":   _REG_FAMILY_SP,
    "ESP":  _REG_FAMILY_SP,
    "BPL":  _REG_FAMILY_BP,
    "BP":   _REG_FAMILY_BP,
    "EBP":  _REG_FAMILY_BP,
    "IP":   _REG_FAMILY_IP,
    "EIP":  _REG_FAMILY_IP,
    "XMM0": _REG_FAMILY_XMM0,
    "YMM0": _REG_FAMILY_XMM0,
    "ZMM0": _REG_FAMILY_XMM0,
    "XMM1": _REG_FAMILY_XMM1,
    "YMM1": _REG_FAMILY_XMM1,
    "ZMM1": _REG_FAMILY_XMM1,
    "XMM2": _REG_FAMILY_XMM2,
    "YMM2": _REG_FAMILY_XMM2,
    "ZMM2": _REG_FAMILY_XMM2,
    "XMM3": _REG_FAMILY_XMM3,
    "YMM3": _REG_FAMILY_XMM3,
    "ZMM3": _REG_FAMILY_XMM3,
    "XMM4": _REG_FAMILY_XMM4,
    "YMM4": _REG_FAMILY_XMM4,
    "ZMM4": _REG_FAMILY_XMM4,
    "XMM5": _REG_FAMILY_XMM5,
    "YMM5": _REG_FAMILY_XMM5,
    "ZMM5": _REG_FAMILY_XMM5,
    "XMM6": _REG_FAMILY_XMM6,
    "YMM6": _REG_FAMILY_XMM6,
    "ZMM6": _REG_FAMILY_XMM6,
    "XMM7": _REG_FAMILY_XMM7,
    "YMM7": _REG_FAMILY_XMM7,
    "ZMM7": _REG_FAMILY_XMM7,
    "XMM8": _REG_FAMILY_XMM8,
    "YMM8": _REG_FAMILY_XMM8,
    "ZMM8": _REG_FAMILY_XMM8,
    "XMM9": _REG_FAMILY_XMM9,
    "YMM9": _REG_FAMILY_XMM9,
    "ZMM9": _REG_FAMILY_XMM9,

    "XMM10": _REG_FAMILY_XMM10,
    "YMM10": _REG_FAMILY_XMM10,
    "ZMM10": _REG_FAMILY_XMM10,
    "XMM11": _REG_FAMILY_XMM11,
    "YMM11": _REG_FAMILY_XMM11,
    "ZMM11": _REG_FAMILY_XMM11,
    "XMM12": _REG_FAMILY_XMM12,
    "YMM12": _REG_FAMILY_XMM12,
    "ZMM12": _REG_FAMILY_XMM12,
    "XMM13": _REG_FAMILY_XMM13,
    "YMM13": _REG_FAMILY_XMM13,
    "ZMM13": _REG_FAMILY_XMM13,
    "XMM14": _REG_FAMILY_XMM14,
    "YMM14": _REG_FAMILY_XMM14,
    "ZMM14": _REG_FAMILY_XMM14,
    "XMM15": _REG_FAMILY_XMM15,
    "YMM15": _REG_FAMILY_XMM15,
    "ZMM15": _REG_FAMILY_XMM15,
    "XMM16": _REG_FAMILY_XMM16,
    "YMM16": _REG_FAMILY_XMM16,
    "ZMM16": _REG_FAMILY_XMM16,
    "XMM17": _REG_FAMILY_XMM17,
    "YMM17": _REG_FAMILY_XMM17,
    "ZMM17": _REG_FAMILY_XMM17,
    "XMM18": _REG_FAMILY_XMM18,
    "YMM18": _REG_FAMILY_XMM18,
    "ZMM18": _REG_FAMILY_XMM18,
    "XMM19": _REG_FAMILY_XMM19,
    "YMM19": _REG_FAMILY_XMM19,
    "ZMM19": _REG_FAMILY_XMM19,

    "XMM20": _REG_FAMILY_XMM20,
    "YMM20": _REG_FAMILY_XMM20,
    "ZMM20": _REG_FAMILY_XMM20,
    "XMM21": _REG_FAMILY_XMM21,
    "YMM21": _REG_FAMILY_XMM21,
    "ZMM21": _REG_FAMILY_XMM21,
    "XMM22": _REG_FAMILY_XMM22,
    "YMM22": _REG_FAMILY_XMM22,
    "ZMM22": _REG_FAMILY_XMM22,
    "XMM23": _REG_FAMILY_XMM23,
    "YMM23": _REG_FAMILY_XMM23,
    "ZMM23": _REG_FAMILY_XMM23,
    "XMM24": _REG_FAMILY_XMM24,
    "YMM24": _REG_FAMILY_XMM24,
    "ZMM24": _REG_FAMILY_XMM24,
    "XMM25": _REG_FAMILY_XMM25,
    "YMM25": _REG_FAMILY_XMM25,
    "ZMM25": _REG_FAMILY_XMM25,
    "XMM26": _REG_FAMILY_XMM26,
    "YMM26": _REG_FAMILY_XMM26,
    "ZMM26": _REG_FAMILY_XMM26,
    "XMM27": _REG_FAMILY_XMM27,
    "YMM27": _REG_FAMILY_XMM27,
    "ZMM27": _REG_FAMILY_XMM27,
    "XMM28": _REG_FAMILY_XMM28,
    "YMM28": _REG_FAMILY_XMM28,
    "ZMM28": _REG_FAMILY_XMM28,
    "XMM29": _REG_FAMILY_XMM29,
    "YMM29": _REG_FAMILY_XMM29,
    "ZMM29": _REG_FAMILY_XMM29,

    "XMM30": _REG_FAMILY_XMM30,
    "YMM30": _REG_FAMILY_XMM30,
    "ZMM30": _REG_FAMILY_XMM30,
    "XMM31": _REG_FAMILY_XMM31,
    "YMM31": _REG_FAMILY_XMM31,
    "ZMM31": _REG_FAMILY_XMM31,

    "MM0": (("MM0", 0, 8),),
    "MM1": (("MM1", 0, 8),),
    "MM2": (("MM2", 0, 8),),
    "MM3": (("MM3", 0, 8),),
    "MM4": (("MM4", 0, 8),),
    "MM5": (("MM5", 0, 8),),
    "MM6": (("MM6", 0, 8),),
    "MM7": (("MM7", 0, 8),),

    "ST0": (("ST0", 0, 10), ("ST0", 0, 12), ("ST0", 0, 16)),
    "ST1": (("ST1", 0, 10), ("ST1", 0, 12), ("ST1", 0, 16)),
    "ST2": (("ST2", 0, 10), ("ST2", 0, 12), ("ST2", 0, 16)),
    "ST3": (("ST3", 0, 10), ("ST3", 0, 12), ("ST3", 0, 16)),
    "ST4": (("ST4", 0, 10), ("ST4", 0, 12), ("ST4", 0, 16)),
    "ST5": (("ST5", 0, 10), ("ST5", 0, 12), ("ST5", 0, 16)),
    "ST6": (("ST6", 0, 10), ("ST6", 0, 12), ("ST6", 0, 16)),
    "ST7": (("ST7", 0, 10), ("ST7", 0, 12), ("ST7", 0, 16)),
  }

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
      "offset": abs(num_bytes_popped) + 4,
      "type": "I"
    }

  def pointer_size(self):
    return 4

  def register_family(self, reg_name):
    return self._REG_FAMILY[reg_name]


class AArch64Arch(Arch):
  """AArch64-specific architecture description (ARMv8, 64-bit)."""

  # TODO(pag): Implement aarch64 register family stuff.

  _REG_FAMILY_Xn = lambda l: (
    ("X{}".format(l), 0, 8),
    ("W{}".format(l), 0, 4),
  )

  _REG_FAMILY_X0 = _REG_FAMILY_Xn(0)
  _REG_FAMILY_X1 = _REG_FAMILY_Xn(1)
  _REG_FAMILY_X2 = _REG_FAMILY_Xn(2)
  _REG_FAMILY_X3 = _REG_FAMILY_Xn(3)
  _REG_FAMILY_X4 = _REG_FAMILY_Xn(4)
  _REG_FAMILY_X5 = _REG_FAMILY_Xn(5)
  _REG_FAMILY_X6 = _REG_FAMILY_Xn(6)
  _REG_FAMILY_X7 = _REG_FAMILY_Xn(7)
  _REG_FAMILY_X8 = _REG_FAMILY_Xn(8)
  _REG_FAMILY_X9 = _REG_FAMILY_Xn(9)
  _REG_FAMILY_X10 = _REG_FAMILY_Xn(10)
  _REG_FAMILY_X11 = _REG_FAMILY_Xn(11)
  _REG_FAMILY_X12 = _REG_FAMILY_Xn(12)
  _REG_FAMILY_X13 = _REG_FAMILY_Xn(13)
  _REG_FAMILY_X14 = _REG_FAMILY_Xn(14)
  _REG_FAMILY_X15 = _REG_FAMILY_Xn(15)
  _REG_FAMILY_X16 = _REG_FAMILY_Xn(16)
  _REG_FAMILY_X17 = _REG_FAMILY_Xn(17)
  _REG_FAMILY_X18 = _REG_FAMILY_Xn(18)
  _REG_FAMILY_X19 = _REG_FAMILY_Xn(19)
  _REG_FAMILY_X20 = _REG_FAMILY_Xn(20)
  _REG_FAMILY_X21 = _REG_FAMILY_Xn(21)
  _REG_FAMILY_X22 = _REG_FAMILY_Xn(22)
  _REG_FAMILY_X23 = _REG_FAMILY_Xn(23)
  _REG_FAMILY_X24 = _REG_FAMILY_Xn(24)
  _REG_FAMILY_X25 = _REG_FAMILY_Xn(25)
  _REG_FAMILY_X26 = _REG_FAMILY_Xn(26)
  _REG_FAMILY_X27 = _REG_FAMILY_Xn(27)
  _REG_FAMILY_X28 = _REG_FAMILY_Xn(28)
  _REG_FAMILY_X29 = _REG_FAMILY_Xn(29)
  _REG_FAMILY_X30 = _REG_FAMILY_Xn(30)

  _REG_FAMILY_SP = {
    ("SP", 0, 8),
    ("WSP", 0, 4),
  }

  _REG_FAMILY_ZR = {
    ("ZR", 0, 8),
    ("WZR", 0, 4),
  }

  _REG_FAMILY_Vn = lambda l: (
    ("V{}".format(l), 0, 16),
    ("Q{}".format(l), 0, 16),
    ("D{}".format(l), 0, 8),
    ("S{}".format(l), 0, 4),
    ("H{}".format(l), 0, 2),
    ("B{}".format(l), 0, 1),
  )

  _REG_FAMILY_V0 = _REG_FAMILY_Vn(0)
  _REG_FAMILY_V1 = _REG_FAMILY_Vn(1)
  _REG_FAMILY_V2 = _REG_FAMILY_Vn(2)
  _REG_FAMILY_V3 = _REG_FAMILY_Vn(3)
  _REG_FAMILY_V4 = _REG_FAMILY_Vn(4)
  _REG_FAMILY_V5 = _REG_FAMILY_Vn(5)
  _REG_FAMILY_V6 = _REG_FAMILY_Vn(6)
  _REG_FAMILY_V7 = _REG_FAMILY_Vn(7)
  _REG_FAMILY_V8 = _REG_FAMILY_Vn(8)
  _REG_FAMILY_V9 = _REG_FAMILY_Vn(9)
  _REG_FAMILY_V10 = _REG_FAMILY_Vn(10)
  _REG_FAMILY_V11 = _REG_FAMILY_Vn(11)
  _REG_FAMILY_V12 = _REG_FAMILY_Vn(12)
  _REG_FAMILY_V13 = _REG_FAMILY_Vn(13)
  _REG_FAMILY_V14 = _REG_FAMILY_Vn(14)
  _REG_FAMILY_V15 = _REG_FAMILY_Vn(15)
  _REG_FAMILY_V16 = _REG_FAMILY_Vn(16)
  _REG_FAMILY_V17 = _REG_FAMILY_Vn(17)
  _REG_FAMILY_V18 = _REG_FAMILY_Vn(18)
  _REG_FAMILY_V19 = _REG_FAMILY_Vn(19)
  _REG_FAMILY_V20 = _REG_FAMILY_Vn(20)
  _REG_FAMILY_V21 = _REG_FAMILY_Vn(21)
  _REG_FAMILY_V22 = _REG_FAMILY_Vn(22)
  _REG_FAMILY_V23 = _REG_FAMILY_Vn(23)
  _REG_FAMILY_V24 = _REG_FAMILY_Vn(24)
  _REG_FAMILY_V25 = _REG_FAMILY_Vn(25)
  _REG_FAMILY_V26 = _REG_FAMILY_Vn(26)
  _REG_FAMILY_V27 = _REG_FAMILY_Vn(27)
  _REG_FAMILY_V28 = _REG_FAMILY_Vn(28)
  _REG_FAMILY_V29 = _REG_FAMILY_Vn(29)
  _REG_FAMILY_V30 = _REG_FAMILY_Vn(30)
  _REG_FAMILY_V31 = _REG_FAMILY_Vn(31)

  _REG_FAMILY = {
    "X0": _REG_FAMILY_X0,
    "X1": _REG_FAMILY_X1,
    "X2": _REG_FAMILY_X2,
    "X3": _REG_FAMILY_X3,
    "X4": _REG_FAMILY_X4,
    "X5": _REG_FAMILY_X5,
    "X6": _REG_FAMILY_X6,
    "X7": _REG_FAMILY_X7,
    "X8": _REG_FAMILY_X8,
    "X9": _REG_FAMILY_X9,
    "X10": _REG_FAMILY_X10,
    "X11": _REG_FAMILY_X11,
    "X12": _REG_FAMILY_X12,
    "X13": _REG_FAMILY_X13,
    "X14": _REG_FAMILY_X14,
    "X15": _REG_FAMILY_X15,
    "X16": _REG_FAMILY_X16,
    "X17": _REG_FAMILY_X17,
    "X18": _REG_FAMILY_X18,
    "X19": _REG_FAMILY_X19,
    "X20": _REG_FAMILY_X20,
    "X21": _REG_FAMILY_X21,
    "X22": _REG_FAMILY_X22,
    "X23": _REG_FAMILY_X23,
    "X24": _REG_FAMILY_X24,
    "X25": _REG_FAMILY_X25,
    "X26": _REG_FAMILY_X26,
    "X27": _REG_FAMILY_X27,
    "X28": _REG_FAMILY_X28,
    "X29": _REG_FAMILY_X29,
    "X30": _REG_FAMILY_X30,
    "SP": _REG_FAMILY_SP,
    "XZR": _REG_FAMILY_ZR,

    "W0": _REG_FAMILY_X0,
    "W1": _REG_FAMILY_X1,
    "W2": _REG_FAMILY_X2,
    "W3": _REG_FAMILY_X3,
    "W4": _REG_FAMILY_X4,
    "W5": _REG_FAMILY_X5,
    "W6": _REG_FAMILY_X6,
    "W7": _REG_FAMILY_X7,
    "W8": _REG_FAMILY_X8,
    "W9": _REG_FAMILY_X9,
    "W10": _REG_FAMILY_X10,
    "W11": _REG_FAMILY_X11,
    "W12": _REG_FAMILY_X12,
    "W13": _REG_FAMILY_X13,
    "W14": _REG_FAMILY_X14,
    "W15": _REG_FAMILY_X15,
    "W16": _REG_FAMILY_X16,
    "W17": _REG_FAMILY_X17,
    "W18": _REG_FAMILY_X18,
    "W19": _REG_FAMILY_X19,
    "W20": _REG_FAMILY_X20,
    "W21": _REG_FAMILY_X21,
    "W22": _REG_FAMILY_X22,
    "W23": _REG_FAMILY_X23,
    "W24": _REG_FAMILY_X24,
    "W25": _REG_FAMILY_X25,
    "W26": _REG_FAMILY_X26,
    "W27": _REG_FAMILY_X27,
    "W28": _REG_FAMILY_X28,
    "W29": _REG_FAMILY_X29,
    "W30": _REG_FAMILY_X30,
    "WSP": _REG_FAMILY_SP,
    "WZR": _REG_FAMILY_ZR,
    "PC": (("PC", 0, 8),),

    "V0": _REG_FAMILY_V0,
    "V1": _REG_FAMILY_V1,
    "V2": _REG_FAMILY_V2,
    "V3": _REG_FAMILY_V3,
    "V4": _REG_FAMILY_V4,
    "V5": _REG_FAMILY_V5,
    "V6": _REG_FAMILY_V6,
    "V7": _REG_FAMILY_V7,
    "V8": _REG_FAMILY_V8,
    "V9": _REG_FAMILY_V9,
    "V10": _REG_FAMILY_V10,
    "V11": _REG_FAMILY_V11,
    "V12": _REG_FAMILY_V12,
    "V13": _REG_FAMILY_V13,
    "V14": _REG_FAMILY_V14,
    "V15": _REG_FAMILY_V15,
    "V16": _REG_FAMILY_V16,
    "V17": _REG_FAMILY_V17,
    "V18": _REG_FAMILY_V18,
    "V19": _REG_FAMILY_V19,
    "V20": _REG_FAMILY_V20,
    "V21": _REG_FAMILY_V21,
    "V22": _REG_FAMILY_V22,
    "V23": _REG_FAMILY_V23,
    "V24": _REG_FAMILY_V24,
    "V25": _REG_FAMILY_V25,
    "V26": _REG_FAMILY_V26,
    "V27": _REG_FAMILY_V27,
    "V28": _REG_FAMILY_V28,
    "V29": _REG_FAMILY_V29,
    "V30": _REG_FAMILY_V30,
    "V31": _REG_FAMILY_V31,

    "Q0": _REG_FAMILY_V0,
    "Q1": _REG_FAMILY_V1,
    "Q2": _REG_FAMILY_V2,
    "Q3": _REG_FAMILY_V3,
    "Q4": _REG_FAMILY_V4,
    "Q5": _REG_FAMILY_V5,
    "Q6": _REG_FAMILY_V6,
    "Q7": _REG_FAMILY_V7,
    "Q8": _REG_FAMILY_V8,
    "Q9": _REG_FAMILY_V9,
    "Q10": _REG_FAMILY_V10,
    "Q11": _REG_FAMILY_V11,
    "Q12": _REG_FAMILY_V12,
    "Q13": _REG_FAMILY_V13,
    "Q14": _REG_FAMILY_V14,
    "Q15": _REG_FAMILY_V15,
    "Q16": _REG_FAMILY_V16,
    "Q17": _REG_FAMILY_V17,
    "Q18": _REG_FAMILY_V18,
    "Q19": _REG_FAMILY_V19,
    "Q20": _REG_FAMILY_V20,
    "Q21": _REG_FAMILY_V21,
    "Q22": _REG_FAMILY_V22,
    "Q23": _REG_FAMILY_V23,
    "Q24": _REG_FAMILY_V24,
    "Q25": _REG_FAMILY_V25,
    "Q26": _REG_FAMILY_V26,
    "Q27": _REG_FAMILY_V27,
    "Q28": _REG_FAMILY_V28,
    "Q29": _REG_FAMILY_V29,
    "Q30": _REG_FAMILY_V30,
    "Q31": _REG_FAMILY_V31,

    "D0": _REG_FAMILY_V0,
    "D1": _REG_FAMILY_V1,
    "D2": _REG_FAMILY_V2,
    "D3": _REG_FAMILY_V3,
    "D4": _REG_FAMILY_V4,
    "D5": _REG_FAMILY_V5,
    "D6": _REG_FAMILY_V6,
    "D7": _REG_FAMILY_V7,
    "D8": _REG_FAMILY_V8,
    "D9": _REG_FAMILY_V9,
    "D10": _REG_FAMILY_V10,
    "D11": _REG_FAMILY_V11,
    "D12": _REG_FAMILY_V12,
    "D13": _REG_FAMILY_V13,
    "D14": _REG_FAMILY_V14,
    "D15": _REG_FAMILY_V15,
    "D16": _REG_FAMILY_V16,
    "D17": _REG_FAMILY_V17,
    "D18": _REG_FAMILY_V18,
    "D19": _REG_FAMILY_V19,
    "D20": _REG_FAMILY_V20,
    "D21": _REG_FAMILY_V21,
    "D22": _REG_FAMILY_V22,
    "D23": _REG_FAMILY_V23,
    "D24": _REG_FAMILY_V24,
    "D25": _REG_FAMILY_V25,
    "D26": _REG_FAMILY_V26,
    "D27": _REG_FAMILY_V27,
    "D28": _REG_FAMILY_V28,
    "D29": _REG_FAMILY_V29,
    "D30": _REG_FAMILY_V30,
    "D31": _REG_FAMILY_V31,

    "S0": _REG_FAMILY_V0,
    "S1": _REG_FAMILY_V1,
    "S2": _REG_FAMILY_V2,
    "S3": _REG_FAMILY_V3,
    "S4": _REG_FAMILY_V4,
    "S5": _REG_FAMILY_V5,
    "S6": _REG_FAMILY_V6,
    "S7": _REG_FAMILY_V7,
    "S8": _REG_FAMILY_V8,
    "S9": _REG_FAMILY_V9,
    "S10": _REG_FAMILY_V10,
    "S11": _REG_FAMILY_V11,
    "S12": _REG_FAMILY_V12,
    "S13": _REG_FAMILY_V13,
    "S14": _REG_FAMILY_V14,
    "S15": _REG_FAMILY_V15,
    "S16": _REG_FAMILY_V16,
    "S17": _REG_FAMILY_V17,
    "S18": _REG_FAMILY_V18,
    "S19": _REG_FAMILY_V19,
    "S20": _REG_FAMILY_V20,
    "S21": _REG_FAMILY_V21,
    "S22": _REG_FAMILY_V22,
    "S23": _REG_FAMILY_V23,
    "S24": _REG_FAMILY_V24,
    "S25": _REG_FAMILY_V25,
    "S26": _REG_FAMILY_V26,
    "S27": _REG_FAMILY_V27,
    "S28": _REG_FAMILY_V28,
    "S29": _REG_FAMILY_V29,
    "S30": _REG_FAMILY_V30,
    "S31": _REG_FAMILY_V31,

    "H0": _REG_FAMILY_V0,
    "H1": _REG_FAMILY_V1,
    "H2": _REG_FAMILY_V2,
    "H3": _REG_FAMILY_V3,
    "H4": _REG_FAMILY_V4,
    "H5": _REG_FAMILY_V5,
    "H6": _REG_FAMILY_V6,
    "H7": _REG_FAMILY_V7,
    "H8": _REG_FAMILY_V8,
    "H9": _REG_FAMILY_V9,
    "H10": _REG_FAMILY_V10,
    "H11": _REG_FAMILY_V11,
    "H12": _REG_FAMILY_V12,
    "H13": _REG_FAMILY_V13,
    "H14": _REG_FAMILY_V14,
    "H15": _REG_FAMILY_V15,
    "H16": _REG_FAMILY_V16,
    "H17": _REG_FAMILY_V17,
    "H18": _REG_FAMILY_V18,
    "H19": _REG_FAMILY_V19,
    "H20": _REG_FAMILY_V20,
    "H21": _REG_FAMILY_V21,
    "H22": _REG_FAMILY_V22,
    "H23": _REG_FAMILY_V23,
    "H24": _REG_FAMILY_V24,
    "H25": _REG_FAMILY_V25,
    "H26": _REG_FAMILY_V26,
    "H27": _REG_FAMILY_V27,
    "H28": _REG_FAMILY_V28,
    "H29": _REG_FAMILY_V29,
    "H30": _REG_FAMILY_V30,
    "H31": _REG_FAMILY_V31,

    "B0": _REG_FAMILY_V0,
    "B1": _REG_FAMILY_V1,
    "B2": _REG_FAMILY_V2,
    "B3": _REG_FAMILY_V3,
    "B4": _REG_FAMILY_V4,
    "B5": _REG_FAMILY_V5,
    "B6": _REG_FAMILY_V6,
    "B7": _REG_FAMILY_V7,
    "B8": _REG_FAMILY_V8,
    "B9": _REG_FAMILY_V9,
    "B10": _REG_FAMILY_V10,
    "B11": _REG_FAMILY_V11,
    "B12": _REG_FAMILY_V12,
    "B13": _REG_FAMILY_V13,
    "B14": _REG_FAMILY_V14,
    "B15": _REG_FAMILY_V15,
    "B16": _REG_FAMILY_V16,
    "B17": _REG_FAMILY_V17,
    "B18": _REG_FAMILY_V18,
    "B19": _REG_FAMILY_V19,
    "B20": _REG_FAMILY_V20,
    "B21": _REG_FAMILY_V21,
    "B22": _REG_FAMILY_V22,
    "B23": _REG_FAMILY_V23,
    "B24": _REG_FAMILY_V24,
    "B25": _REG_FAMILY_V25,
    "B26": _REG_FAMILY_V26,
    "B27": _REG_FAMILY_V27,
    "B28": _REG_FAMILY_V28,
    "B29": _REG_FAMILY_V29,
    "B30": _REG_FAMILY_V30,
    "B31": _REG_FAMILY_V31,

    "TPIDR_EL0": (("TPIDR_EL0", 0, 8),),
    "TPIDRRO_EL0": (("TPIDRRO_EL0", 0, 8),),
  }

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
      "offset": abs(num_bytes_popped),
      "type": "L"
    }

  def pointer_size(self):
    return 8

