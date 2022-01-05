#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

import binaryninja as bn

from ..util import *

_FLOAT_ARGS_REGS = {
    "x86": ["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"],
    "x86_64": ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"],
    # AAPCS uses integer register for passing floating point arguments
    "armv7": ["r0", "r1", "r2", "r3"],
    # AAPCS_VFP can use s0-15 registers for passing floating point arguments
    "thumb2": ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"],
    # Floating point registers with quad size
    "aarch64": ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
}


class CallingConvention:
    def __init__(self, arch, bn_func: bn.Function, cc):
        self._cc = cc
        self._arch = arch
        self._bn_func = bn_func
        self._int_arg_regs = self._cc.int_arg_regs
        self._float_arg_regs = self._cc.float_arg_regs

        self._int_return_reg = self._cc.int_return_reg
        self._high_int_return_reg = self._cc.high_int_return_reg
        self._float_return_reg = self._cc.float_return_reg

        # if the func calling_convention is None assign 0
        # as the default calling convention
        if self._cc is None:
            self._cc = self._bn_func.arch.calling_conventions[0]

        # set the float_arg_regs for default calling convention (cdecl)
        # for both x86 and arm architectures
        if self._cc.name == "cdecl" or self._cc.name == "sysv":
            try:
                self._float_arg_regs = _FLOAT_ARGS_REGS[self._cc.arch.name]
            except KeyError:
                WARN(f"Unsupported architecture: {self._cc.arch}")

    def is_sysv(self):
        return self._cc.name == "sysv"

    def is_cdecl(self):
        return self._cc.name == "cdecl"

    @property
    def int_arg_reg(self):
        return self._int_arg_regs

    @property
    def float_arg_reg(self):
        return self._float_arg_regs

    @property
    def int_return_reg(self):
        return self._int_return_reg

    @property
    def high_int_return_reg(self):
        return self._high_int_return_reg

    @property
    def float_return_reg(self):
        return self._float_return_reg

    @property
    def next_int_arg_reg(self):
        try:
            reg_name = self._int_arg_regs[0]
            del self._int_arg_regs[0]
            return reg_name
        except:
            return None

    @property
    def next_float_arg_reg(self):
        reg_name = self._float_arg_regs[0]
        del self._float_arg_regs[0]
        return reg_name

    @property
    def return_regs(self):
        if isinstance(self._bn_func, bn.Function):
            for reg in self._bn_func.return_regs:
                yield reg
