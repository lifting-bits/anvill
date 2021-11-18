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

from typing import Optional


import ida_idp
import ida_idaapi
import ida_typeinf
import ida_ida
import ida_nalt


from .idaprogram import *


from ..arch import *
from ..os import *
from ..program import *


def _guess_os():
    """Try to guess the current OS"""
    try:
        abi_name = ida_typeinf.get_abi_name()
    except:
        abi_name = ida_nalt.get_abi_name()

    if "OSX" == abi_name:
        return "macos"

    inf = ida_idaapi.get_inf_structure()
    file_type = inf.filetype
    if file_type in (ida_ida.f_ELF, ida_ida.f_AOUT, ida_ida.f_COFF):
        return "linux"
    elif file_type == ida_ida.f_MACHO:
        return "macos"
    elif file_type in (
        ida_ida.f_PE,
        ida_ida.f_EXE,
        ida_ida.f_EXE_old,
        ida_ida.f_COM,
        ida_ida.f_COM_old,
    ):
        return "windows"
    else:
        raise UnhandledOSException("Unrecognized OS type")


def _guess_architecture():
    """Try to guess the current architecture."""

    reg_names = ida_idp.ph_get_regnames()
    inf = ida_idaapi.get_inf_structure()

    if "ax" in reg_names and "xmm0" in reg_names:
        if inf.is_64bit():
            return "amd64"
        else:
            return "x86"

    elif "ARM" in inf.procName:
        if inf.is_64bit():
            return "aarch64"
        elif inf.is_32bit():
            return "aarch32"
        else:
            raise UnhandledArchitectureType(
                "Unrecognized 32-bit ARM architecture: {}".format(inf.procName)
            )

    elif "sparc" in inf.procName:
        if inf.is_64bit():
            return "sparc64"
        else:
            return "sparc32"
    else:
        raise UnhandledArchitectureType(
            "Unrecognized archictecture: {}".format(inf.procName)
        )


def _get_arch():
    """Arch class that gives access to architecture-specific functionality."""
    name = _guess_architecture()
    if name == "amd64":
        return AMD64Arch()
    elif name == "x86":
        return X86Arch()
    elif name == "aarch64":
        return AArch64Arch()
    elif name == "aarch32":
        return AArch32Arch()
    elif name == "sparc32":
        return Sparc32Arch()
    elif name == "sparc64":
        return Sparc64Arch()
    else:
        raise UnhandledArchitectureType(
            "Missing architecture object type for architecture '{}'".format(name)
        )


def _get_os():
    """OS class that gives access to OS-specific functionality."""
    name = _guess_os()
    if name == "linux":
        return LinuxOS()
    elif name == "macos":
        return MacOS()
    elif name == "windows":
        return WindowsOS()
    elif name == "solaris":
        return SolarisOS()
    else:
        raise UnhandledOSException(
            "Missing operating system object type for OS '{}'".format(name)
        )


def get_program(
    arch: Optional[str] = None,
    os: Optional[str] = None,
    maybe_base_address: Optional[int] = None,
    cache: bool = False,
) -> Optional[Program]:
    if cache:
        DEBUG("Ignoring deprecated `cache` parameter to anvill.get_program")

    if not arch:
        arch = _get_arch()

    if not os:
        os = _get_os()

    return IDAProgram(arch, os, maybe_base_address)
