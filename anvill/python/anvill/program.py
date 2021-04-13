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


import collections
from dataclasses import dataclass, field
from typing import List, Dict

from .function import *
from .var import *
from .mem import *
from .exc import *


@dataclass
class ControlFlowTargetList:
    """A list of targets reachable from a given address"""

    source: int = 0
    destination_list: List[int] = field(default_factory=list)
    complete: bool = False


class Program(object):
    """Represents a program."""

    def __init__(self, arch, os):
        self._arch = arch
        self._os = os
        self._memory = Memory()
        self._var_defs = {}
        self._var_decls = {}
        self._func_defs = {}
        self._func_decls = {}
        self._control_flow_redirections = {}
        self._ctrl_flow_targets: Dict[int, ControlFlowTargetList] = {}
        self._symbols = collections.defaultdict(set)

    def get_symbols(self, ea):
        syms = self._symbols[ea]
        if ea in self._symbols:
            yield from iter(syms)
        else:
            for name in self.get_symbols_impl(ea):
                old_len = len(syms)
                syms.add(name)
                if old_len < len(syms):
                    yield name

    def get_function(self, ea):
        if ea in self._func_defs:
            return self._func_defs[ea]
        elif ea in self._func_decls:
            return self._func_decls[ea]
        else:
            return self.get_function_impl(ea)

    def get_variable(self, ea):
        if ea in self._var_defs:
            return self._var_defs[ea]
        elif ea in self._var_decls:
            return self._var_decls[ea]
        else:
            return self.get_variable_impl(ea)

    def get_symbols_impl(self, ea):
        raise NotImplementedError()

    def get_function_impl(self, ea):
        raise NotImplementedError()

    def get_variable_impl(self, ea):
        raise NotImplementedError()

    def add_symbol(self, ea, name):
        if len(name):
            self._symbols[ea].add(name)

    def add_variable_declaration(self, ea, add_refs_as_defs=False):
        var = self.get_variable(ea)
        if isinstance(var, Variable):
            ea = var.address()
            if ea not in self._var_defs and ea not in self._var_decls:
                self._var_decls[ea] = var
                var.visit(self, False, add_refs_as_defs)
            return True
        else:
            return False

    def add_control_flow_redirection(self, source_ea: int , destination_ea: int) -> bool:
        if type(source_ea) != int or type(destination_ea) != int:
            return False

        if source_ea in self._control_flow_redirections:
            return False

        self._control_flow_redirections[source_ea] = destination_ea
        return True

    def add_variable_definition(self, ea, add_refs_as_defs=False):
        var = self.get_variable(ea)
        if isinstance(var, Variable):
            ea = var.address()
            if ea not in self._var_defs:
                if ea in self._var_decls:
                    del self._var_decls[ea]
                self._var_defs[ea] = var
                var.visit(self, True, add_refs_as_defs)
            return True
        else:
            return False

    def add_function_definition(self, ea, add_refs_as_defs=False):
        func = self.get_function(ea)
        if isinstance(func, Function):
            ea = func.address()
            if ea not in self._func_defs:
                if ea in self._func_decls:
                    del self._func_decls[ea]
                self._func_defs[ea] = func
                func.visit(self, True, add_refs_as_defs)
            return True
        else:
            return False

    def add_function_declaration(self, ea, add_refs_as_defs=False):
        func = self.get_function(ea)
        if isinstance(func, Function):
            ea = func.address()
            if ea not in self._func_defs and ea not in self._func_decls:
                self._func_decls[ea] = func
                func.visit(self, False, add_refs_as_defs)
            return True
        else:
            return False

    def set_control_flow_targets(self, source: int, destination_list: List[int], complete: bool):
        if source in self._ctrl_flow_targets:
            return False

        entry = ControlFlowTargetList()
        entry.source = source
        entry.destination_list = destination_list
        entry.complete = complete

        self._ctrl_flow_targets[entry.source] = entry
        return True

    def try_add_referenced_entity(self, ea, add_refs_as_defs=False):
        if add_refs_as_defs:
            try:
                self.add_function_definition(ea, add_refs_as_defs)
                return True
            except InvalidFunctionException as e1:
                try:
                    self.add_variable_definition(ea, add_refs_as_defs)
                    return True
                except InvalidVariableException as e2:
                    pass
        try:
            self.add_function_declaration(ea, False)
            return True
        except InvalidFunctionException as e1:
            try:
                self.add_variable_declaration(ea, False)
                return True
            except InvalidVariableException as e2:
                return False

    def memory(self):
        return self._memory

    def proto(self):
        proto = {}
        proto["arch"] = self._arch.name()
        proto["os"] = self._os.name()
        proto["functions"] = []
        proto["control_flow_redirections"] = []
        proto["control_flow_targets"] = []
        proto["variables"] = []
        proto["symbols"] = []

        for ea, names in self._symbols.items():
            for name in names:
                proto["symbols"].append([ea, name])

        for func in self._func_decls.values():
            proto["functions"].append(func.proto())

        for func in self._func_defs.values():
            proto["functions"].append(func.proto())

        for source, target in self._control_flow_redirections.items():
            # Use 2-entry lists so that we don't use 'source' as a key. That
            # would turn it into a string in the final JSON forcing us to
            # handle integers in two different ways
            proto["control_flow_redirections"].append([source, target])

        for entry in self._ctrl_flow_targets.values():
            obj = {}
            obj["complete"] = entry.complete
            obj["source"] = entry.source
            obj["destination_list"] = entry.destination_list

            proto["control_flow_targets"].append(obj)

        for var in self._var_decls.values():
            proto["variables"].append(var.proto())

        for var in self._var_defs.values():
            proto["variables"].append(var.proto())

        proto["memory"] = self._memory.proto()

        if self._arch.pointer_size() == 4:
            stack_mask = 0x7FFFFFFF
            page_mask = 0x7FFFF000
        else:
            stack_mask = 0x7FFFFFFFFFFF
            page_mask = 0x7FFFFFFFF000

        int_type = stack_mask.__class__

        # Go find the maximum address.
        max_addr = 0
        for range_proto in proto["memory"]:
            max_addr = max(
                max_addr, range_proto["address"] + (len(range_proto["data"]) / 2)
            )

        stack_base = (
            int_type(max_addr + int_type((stack_mask - max_addr) * 5.0 / 8.0))
            & page_mask
        )

        proto["stack"] = {"address": stack_base, "size": 24576, "start_offset": 4096}

        return proto
