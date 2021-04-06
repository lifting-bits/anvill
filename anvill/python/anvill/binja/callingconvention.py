# Copyright (c) 2020-present Trail of Bits, Inc.
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


class CallingConvention:

    _FLOAT_ARGS_REG = {
        "x86": ["st0", "st1", "st2", "st3", "st4", "st5"],
        "amd64": ["st0", "st1", "st2", "st3", "st4", "st5"],
        # AAPCS uses integer register for passing floating point arguments
        "armv7": ["r0", "r1", "r2", "r3"],
        # AAPCS_VFP can use s0-15 registers for passing floating point arguments
        "thumb2": ["s0", "s1", "s2", "s4", "s5", "s6", "s7"]
    }

    def __init__(self, arch, bn_func):
        self._cc = bn_func.calling_convention
        self._arch = arch
        self._bn_func = bn_func
        self._int_arg_regs = self._cc.int_arg_regs
        self._float_arg_regs = self._cc.float_arg_regs

        # set the float_arg_regs for default calling convention (cdecl)
        # for both x86 and arm architectures
        if self._cc.name == "cdecl":
            try:
                self._float_arg_regs = CallingConvention._FLOAT_ARGS_REG[self._cc.arch.name]
            except IndexError:
                DEBUG("Unsupported architecture: {}".format(self._cc.arch.name))

    def is_sysv(self):
        return self._cc.name == "sysv"

    def is_cdecl(self):
        return self._cc.name == "cdecl"

    @property
    def next_int_arg_reg(self):
        try:
            reg_name = self._int_arg_regs[0]
            del self._int_arg_regs[0]
            return reg_name
        except:
            return "invalid int register"

    @property
    def next_float_arg_reg(self):
        reg_name = self._float_arg_regs[0]
        del self._float_arg_regs[0]
        return reg_name

    @property
    def return_regs(self):
        for reg in self._bn_func.return_regs:
            yield reg