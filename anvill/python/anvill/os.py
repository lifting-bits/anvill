# Copyright (c) 2020 Trail of Bits, Inc.
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


from abc import ABC, abstractmethod
from typing import NewType, cast

from .arch import Arch

CC = NewType('CC', int)

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
