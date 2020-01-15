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


import json


from .function import *
from .var import *
from .mem import *
from .exc import *


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

  def get_function(self, ea):
    raise NotImplementedError()

  def get_variable(self, ea):
    raise NotImplementedError()

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

  def try_add_referenced_entity(self, ea, add_refs_as_defs=False):
    try:
      if add_refs_as_defs:
        self.add_function_definition(ea, add_refs_as_defs)
      else:
        self.add_function_declaration(ea, add_refs_as_defs)
      return True
    except InvalidFunctionException as e1:
      try:
        if add_refs_as_defs:
          self.add_variable_definition(ea, add_refs_as_defs)
        else:
          self.add_variable_declaration(ea, add_refs_as_defs)
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
    proto["variables"] = []

    for func in self._func_decls.values():
      proto["functions"].append(func.proto())

    for func in self._func_defs.values():
      proto["functions"].append(func.proto())

    for var in self._var_decls.values():
      proto["variables"].append(var.proto())

    for var in self._var_defs.values():
      proto["variables"].append(var.proto())

    proto["memory"] = self._memory.proto()

    if self._arch.pointer_size() == 4:
      stack_mask = 0x7FFFFFFF
      page_mask = 0x7FFFF000
    else:
      stack_mask = 0x7fffffffffff
      page_mask = 0x7ffffffff000

    int_type = stack_mask.__class__

    # Go find the maximum address.
    max_addr = 0
    for range_proto in proto["memory"]:
      max_addr = max(
          max_addr, range_proto["address"] + (len(range_proto["data"]) / 2))

    stack_base = int_type(
        max_addr + int_type((stack_mask - max_addr) * 5.0/8.0)) & page_mask

    proto["stack"] = {
      "address": stack_base,
      "size": 24576,
      "start_offset": 4096
    }

    return json.dumps(proto)
