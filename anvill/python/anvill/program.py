#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

from abc import ABC, abstractmethod
import collections
from dataclasses import dataclass, field
from typing import List, DefaultDict, Dict, Iterator, Optional, Set, Final

from .os import *
from .function import *
from .var import *
from .mem import *
from .exc import *
import traceback

@dataclass
class ControlFlowTargetList:
    """A list of targets reachable from a given address"""

    source: int = 0
    destination_list: List[int] = field(default_factory=list)
    complete: bool = False


class Specification(ABC):
    """Represents a program."""

    def __init__(self, arch: Arch, os: OS):
        self._arch: Final[Arch] = arch
        self._os: Final[OS] = os
        self._memory: Final[Memory] = Memory()
        self._var_defs: Dict[int, Variable] = {}
        self._var_decls: Dict[int, Variable] = {}
        self._func_defs: Dict[int, Function] = {}
        self._func_decls: Dict[int, Function] = {}
        self._control_flow_redirections: Dict[int, int] = {}
        self._control_flow_targets: Dict[int, ControlFlowTargetList] = {}
        self._symbols: DefaultDict[int, Set[str]] = collections.defaultdict(set)

    def get_symbols(self, ea: int) -> Iterator[str]:
        if ea in self._symbols:
            for sym in self._symbols[ea]:
                yield sym
        else:
            syms: Set[str] = self._symbols[ea]
            for name in self.get_symbols_impl(ea):
                old_len = len(syms)
                syms.add(name)
                if old_len < len(syms):
                    yield name

    def get_function(self, ea: int) -> Optional[Function]:
        if ea in self._func_defs:
            assert ea not in self._func_decls
            return self._func_defs[ea]
        elif ea in self._func_decls:
            return self._func_decls[ea]
        else:
            try:
                return self.get_function_impl(ea)
            except Exception as e:
                raise type(e)(f"Error when trying to get function {ea:x}: {str(e)}") from e

    def get_variable(self, ea: int) -> Optional[Variable]:
        if ea in self._var_defs:
            assert ea not in self._var_decls
            return self._var_defs[ea]
        elif ea in self._var_decls:
            return self._var_decls[ea]
        else:
            try:
                return self.get_variable_impl(ea)
            except Exception as e:
                raise type(e)(f"Error when trying to get variable {ea:x}: {str(e)}") from e

    @abstractmethod
    def get_symbols_impl(self, ea: int) -> Iterator[str]:
        ...

    @abstractmethod
    def get_function_impl(self, ea: int) -> Optional[Function]:
        ...

    @abstractmethod
    def get_variable_impl(self, ea: int) -> Optional[Variable]:
        ...

    def add_symbol(self, ea: int, name: str):
        if len(name):
            self._symbols[ea].add(name)

    def add_variable_declaration(self, ea: int, add_refs_as_defs=False) -> bool:
        var: Optional[Variable] = self.get_variable(ea)
        if var is not None and isinstance(var, Variable):
            ea: int = var.address()
            if ea not in self._var_defs and ea not in self._var_decls:
                self._var_decls[ea] = var
                var.visit(self, False, add_refs_as_defs)
            return True
        else:
            return False

    def add_control_flow_redirection(self, source_ea: int, destination_ea: int):
        assert isinstance(source_ea, int)
        assert isinstance(destination_ea, int)

        self.try_add_referenced_entity(source_ea, False)
        self.try_add_referenced_entity(destination_ea, False)
        self._control_flow_redirections[source_ea] = destination_ea

    def add_variable_definition(self, ea: int, add_refs_as_defs=False) -> bool:
        var: Optional[Variable] = self.get_variable(ea)
        if var is not None and isinstance(var, Variable):
            ea: int = var.address()
            if ea not in self._var_defs:
                if ea in self._var_decls:
                    del self._var_decls[ea]
                self._var_defs[ea] = var
                var.visit(self, True, add_refs_as_defs)
            return True
        else:
            return False

    def add_function_definition(self, ea: int, add_refs_as_defs=False) -> bool:
        func: Optional[Function] = self.get_function(ea)
        if func is not None and isinstance(func, Function):
            ea: int = func.address()
            if ea not in self._func_defs:
                if ea in self._func_decls:
                    del self._func_decls[ea]
                self._func_defs[ea] = func
                func.visit(self, True, add_refs_as_defs)
            return True
        else:
            return False

    def add_function_declaration(self, ea: int, add_refs_as_defs=False) -> bool:
        func: Optional[Function] = self.get_function(ea)
        if func is not None and isinstance(func, Function):
            ea: int = func.address()
            if ea not in self._func_defs and ea not in self._func_decls:
                self._func_decls[ea] = func
                func.visit(self, False, add_refs_as_defs)
            return True
        else:
            return False

    def set_control_flow_targets(
        self, source_ea: int, destination_list: List[int], complete: bool
    ) -> bool:

        self.try_add_referenced_entity(source_ea, False)
        for dest_ea in destination_list:
            self.try_add_referenced_entity(dest_ea, False)

        if source_ea in self._control_flow_targets:
            return False

        entry = ControlFlowTargetList()
        entry.source = source_ea
        entry.destination_list = destination_list
        entry.complete = complete

        self._control_flow_targets[entry.source] = entry
        return True

    def try_add_referenced_entity(self, ea: int, add_refs_as_defs=False) -> bool:
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

    @property
    def memory(self) -> Memory:
        return self._memory

    def proto(self) -> Dict[str, Any]:
        funcs: List[Dict[str, Any]] = []
        symbols: List[Tuple[int, str]] = []
        variables: List[Dict[str, Any]] = []
        redirects: List[Tuple[int, int]] = []
        targets: List[Dict[str, Any]] = []

        for ea, names in self._symbols.items():
            for name in names:
                if len(name):
                    symbols.append((ea, name))

        for func in self._func_decls.values():
            funcs.append(func.proto())

        for func in self._func_defs.values():
            funcs.append(func.proto())

        for var in self._var_decls.values():
            variables.append(var.proto())

        for var in self._var_defs.values():
            variables.append(var.proto())

        # Use two entry lists so that we don't use 'source' as a key. That
        # would turn it into a string in the final JSON forcing us to
        # handle integers in two different ways
        for source, target in self._control_flow_redirections.items():
            redirects.append((source, target))

        for entry in self._control_flow_targets.values():
            destinations = entry.destination_list[:]
            destinations.sort()
            targets.append({
                "source": entry.source,
                "is_complete": entry.complete,
                "destinations": destinations
            })

        funcs.sort(key=lambda o: o["address"])
        variables.sort(key=lambda o: o["address"])
        symbols.sort(key=lambda t: t[0])  # Sort by symbol address.
        redirects.sort(key=lambda t: t[0])  # Sort by source address.
        targets.sort(key=lambda o: o["source"])

        return {
            "arch": self._arch.name(),
            "os": self._os.name(),
            "functions": funcs,
            "variables": variables,
            "symbols": symbols,
            "memory": self._memory.proto(),
            "control_flow_redirections": redirects,
            "control_flow_targets": targets
        }
