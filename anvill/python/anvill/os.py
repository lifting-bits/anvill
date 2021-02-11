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


class OS(object):
    def name(self):
        raise NotImplementedError()


class LinuxOS(OS):
    def name(self):
        return "linux"

    def default_calling_convention(self, arch):
        arch_name = arch.name()
        if arch_name == "x86":
            return 0  # cdecl
        elif arch_name == "amd64":
            return 78  # X86_64_SysV
        else:
            return 0  # cdecl


class MacOS(OS):
    def name(self):
        return "macos"

    def default_calling_convention(self, arch):
        arch_name = arch.name()
        if arch_name == "x86":
            return 0  # cdecl
        elif arch_name == "amd64":
            return 78  # X86_64_SysV
        else:
            return 0  # cdecl


class WindowsOS(OS):
    def name(self):
        return "windows"

    def default_calling_convention(self, arch):
        arch_name = arch.name()
        if arch_name == "x86":
            return 64  # stdcall
        elif arch_name == "amd64":
            return 79  # Win64
        else:
            return 0  # cdecl


class SolarisOS(OS):
    def name(self):
        return "solaris"

    def default_calling_convention(self, arch):
        return 0
