#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from abc import ABC, abstractmethod
from typing import NewType, cast

from .arch import Arch

CC = NewType('CC', int)
DEFAULT_CC = cast(CC, 0)
X86_STDCALL_CC = cast(CC, 64)
X86_CDECL_CC = cast(CC, 0)
X86_THISCALL_CC = cast(CC, 70)
AARCH32_CDECL_CC = cast(CC, 48)


class OS(ABC):
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def default_calling_convention(self, arch: Arch) -> CC:
        ...


class LinuxOS(OS):
    def name(self) -> str:
        return "linux"

    def default_calling_convention(self, arch: Arch) -> CC:
        arch_name = arch.name()
        if arch_name == "x86":
            return cast(CC, 0)  # cdecl
        elif arch_name == "amd64":
            return cast(CC, 78)  # X86_64_SysV
        else:
            return cast(CC, 0)  # cdecl


class MacOS(OS):
    def name(self) -> str:
        return "macos"

    def default_calling_convention(self, arch: Arch) -> CC:
        arch_name = arch.name()
        if arch_name == "x86":
            return cast(CC, 0)  # cdecl
        elif arch_name == "amd64":
            return cast(CC, 78)  # X86_64_SysV
        else:
            return cast(CC, 0)  # cdecl


class WindowsOS(OS):
    def name(self) -> str:
        return "windows"

    def default_calling_convention(self, arch: Arch) -> CC:
        arch_name = arch.name()
        if arch_name == "x86":
            return cast(CC, 64)  # stdcall
        elif arch_name == "amd64":
            return cast(CC, 79)  # Win64
        else:
            return cast(CC, 0)  # cdecl


class SolarisOS(OS):
    def name(self) -> str:
        return "solaris"

    def default_calling_convention(self, arch: Arch) -> CC:
        return cast(CC, 0)
