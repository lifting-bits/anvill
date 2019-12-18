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


import itertools
import weakref


import ida_bytes
import ida_frame
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_xref


from .arch import *
from .exc import *
from .function import *
from .loc import *
from .mem import *
from .os import *
from .program import *
from .type import *


def _guess_os():
  """Try to guess the current OS"""
  abi_name = ida_nalt.get_abi_name()
  if "OSX" == abi_name:
    return "macos"

  inf = ida_idaapi.get_inf_structure()
  file_type = inf.filetype
  if file_type in (ida_ida.f_ELF, ida_ida.f_AOUT, ida_ida.f_COFF):
    return "linux"
  elif file_type == ida_ida.f_MACHO:
    return "macos"
  elif file_type in (ida_ida.g_PE, ida_ida.f_EXE, ida_ida.f_EXE_old, ida_ida.f_COM, ida_ida.f_COM_old):
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
    else:
      raise UnhandledArchitectureType(
          "Unrecognized 32-bit ARM architecture: {}".format(inf.procName))
  else:
    raise UnhandledArchitectureType(
        "Unrecognized archictecture: {}".format(inf.procName))


def _convert_ida_type(tinfo, cache):
  """Convert an IDA `tinfo_t` instance into a `Type` instance."""
  assert isinstance(tinfo, ida_typeinf.tinfo_t)

  if tinfo in cache:
    return cache[tinfo]

  # Void type.
  if tinfo.empty() or tinfo.is_void():
    return VoidType()

  # Pointer, array, or function.
  elif tinfo.is_paf():
    if tinfo.is_ptr():
      ret = PointerType()
      cache[tinfo] = ret
      ret.set_element_type(_convert_ida_type(tinfo.get_pointed_object(), cache))
      return ret

    elif tinfo.is_func():
      ret = FunctionType()
      cache[tinfo] = ret
      ret.set_return_type(_convert_ida_type(tinfo.get_rettype(), cache))
      i = 0
      max_i = tinfo.get_nargs()
      while i < max_i:
        ret.add_parameter_type(_convert_ida_type(tinfo.get_nth_arg(i), cache))
        i += 1

      if tinfo.is_vararg_cc():
        ret.set_is_vararg()

      if tinfo.is_purging_cc():
        ret.set_num_bytes_popped_off_stack(tinfo.calc_purged_bytes())

      return ret

    elif tinfo.is_array():
      ret = ArrayType()
      cache[tinfo] = ret
      ret.set_element_type(_convert_ida_type(tinfo.get_array_element(), cache))
      ret.set_num_elements(tinfo.get_array_nelems())
      return ret

    else:
      raise UnhandledTypeException(
          "Unhandled pointer, array, or function type: {}".format(tinfo.dstr()),
          tinfo)

  # Vector types.
  elif tinfo.is_sse_type():
    ret = VectorType()
    cache[tinfo] = ret
    size = tinfo.get_size()

    # TODO(pag): Do better than this.
    ret.set_element_type(IntegerType(1, False))
    ret.set_num_elements(size)

    return ret

  # Structure, union, or enumerator.
  elif tinfo.is_sue():
    if tinfo.is_udt():  # Structure or union type.
      ret = tinfo.is_struct() and StructureType() or UnionType()
      cache[tinfo] = ret
      i = 0
      max_i = tinfo.get_udt_nmembers()
      while i < max_i:
        udt = ida_typeinf.udt_member_t()
        udt.offset = i
        if not tinfo.find_udt_member(udt, ida_typeinf.STRMEM_INDEX):
          break
        # TODO(pag): bitfields
        # TODO(pag): padding
        ret.add_element_type(_convert_ida_type(udt.type, cache))
        i += 1
      return ret

    elif tinfo.is_enum():
      ret = EnumType()
      cache[tinfo] = ret
      base_type = ida_typeinf.tinfo_t(tinfo.get_enum_base_type())
      ret.set_underlying_type(_convert_ida_type(base_type, cache))
      return ret

    else:
      raise UnhandledTypeException(
          "Unhandled struct, union, or enum type: {}".format(tinfo.dstr()),
          tinfo)
  
  # Boolean type.
  elif tinfo.is_bool():
    return BoolType()
  
  # Integer type.
  elif tinfo.is_integral():
    return IntegerType(tinfo.get_unpadded_size(), tinfo.is_signed())

  # Floating point.
  elif tinfo.is_floating():
    if tinfo.is_ldouble():
      return FloatingPointType(tinfo.get_unpadded_size())
    elif tinfo.is_double():
      return FloatingPointType(8)
    elif tinfo.is_float():
      return FloatingPointType(4)
    else:
      raise UnhandledTypeException(
          "Unhandled floating point type: {}".format(tinfo.dstr()), tinfo)

  elif tinfo.is_complex():
    raise UnhandledTypeException(
        "Complex numbers are not yet handled: {}".format(tinfo.dstr()), tinfo)

  # Type alias/reference.
  elif tinfo.is_typeref():
    ret = TypedefType()
    cache[tinfo] = ret
    ret.set_underlying_type(_convert_ida_type(tinfo.get_realtype(), cache))
    return ret

  else:
    raise UnhandledTypeException(
        "Unhandled type: {}".format(tinfo.dstr()), tinfo)


def _get_arch():
  """Arch class that gives access to architecture-specific functionality."""
  name = _guess_architecture()
  if name == "amd64":
    return AMD64Arch()
  elif name == "x86":
    return X86Arch()
  elif name == "aarch64":
    return AArch64Arch()
  else:
    raise UnhandledArchitectureType(
        "Missing architecture object type for architecture '{}'".format(name))


def _get_os():
  """OS class that gives access to OS-specific functionality."""
  name = _guess_os()
  if name == "linux":
    return LinuxOS()
  elif name == "macos":
    return MacOS()
  elif name == "windows":
    return WindowsOS()
  else:
    raise UnhandledOSException(
        "Missing operating system object type for OS '{}'".format(name))


def get_type(ty):
  """Type class that gives access to type sizes, printings, etc."""
  
  if isinstance(ty, Type):
    return ty

  elif isinstance(ty, Function):
    return ty.type()

  elif isinstance(ty, Location):
    return ty.type()

  elif isinstance(ty, ida_typeinf.tinfo_t):
    return _convert_ida_type(ty, {})

  tif = ida_typeinf.tinfo_t()
  try:
    if not ida_nalt.get_tinfo(tif, ty):
      ida_typeinf.guess_tinfo(tif, ty)
  except:
    pass

  if not tif.empty():
    return _convert_ida_type(tif, {})

  if not ty:
    return VoidType()

  raise UnhandledTypeException("Unrecognized type passed to `Type`.", ty)


def _get_address_sized_reg(arch, reg_name):
  """Given the regiseter name `reg_name`, find the name of the register in the
  same family whose size is the pointer size of this architecture."""

  try:
    family = arch.register_family(reg_name)
    addr_size = arch.pointer_size()
    for f_reg_name, f_reg_offset, f_reg_size in family:
      if 0 == f_reg_offset and addr_size == f_reg_size:
        return f_reg_name
  except:
    pass
  return reg_name


def _expand_locations(arch, pfn, ty, argloc, out_locs):
  """Expand the locations referred to by `argloc` into a list of `Location`s
  in `out_locs`."""

  reg_names = ida_idp.ph_get_regnames()
  where = argloc.atype()

  if where == ida_typeinf.ALOC_STACK:
    sp_adjust_retaddr = int(ida_frame.frame_off_args(pfn) - \
                            ida_frame.frame_off_retaddr(pfn))
    loc = Location()
    loc.set_memory(arch.stack_pointer_name(),
                   argloc.stkoff() + sp_adjust_retaddr)
    loc.set_type(ty)
    out_locs.append(loc)

  # Distributed across two or more locations.
  elif where == ida_typeinf.ALOC_DIST:
    for part in argloc.scattered():
      part_ty = ty.extract(arch, part.off, part.size)
      _expand_locations(arch, pfn, part_ty, part, out_locs)

  # Located in a single register, possibly in a small part of the register
  # itself.
  elif where == ida_typeinf.ALOC_REG1:
    ty_size = ty.size(arch)
    reg_name = reg_names[argloc.reg1()].upper()
    try:
      reg_offset = argloc.regoff()
      family = arch.register_family(reg_name)

      # Try to guess the right name for the register based on the size of the
      # type that it will contain. For example, IDA will tell us register `ax`
      # is used, not specify if it's `al`, `ah`, `eax`, or `rax`.
      #
      # NOTE: The registers in the family tuple are sorted in descending
      #       order of size.
      found = False
      for f_reg_name, f_reg_offset, f_reg_size in family:
        if f_reg_offset != reg_offset:
          continue

        if ty_size == f_reg_size:
          found = True
          reg_name = f_reg_name
          break

      if not found:
        raise Exception()

    except:
      reg_name = (ida_idp.get_reg_name(argloc.reg1(), ty_size) or reg_name).upper()

    loc = Location()
    loc.set_register(reg_name)
    loc.set_type(ty)
    out_locs.append(loc)

  # Located in a pair of registers.
  elif where == ida_typeinf.ALOC_REG2:
    ty_size = ty.size(arch)
    reg_name1 = reg_names[argloc.reg1()].upper()
    reg_name2 = reg_names[argloc.reg2()].upper()
    ty1 = ty.extract(arch, 0, ty_size / 2)
    ty2 = ty.extract(arch, ty_size / 2, ty_size / 2)

    try:
      found = False
      family1 = arch.register_family(reg_name1)
      family2 = arch.register_family(reg_name2)

      # Try to guess which registers IDA actually meant. For example, for
      # an `EDX:EAX` return value, our `ty_size` will be 8 bytes, but IDA will
      # report the registers as `ax` and `dx` (due to those being the names in
      # `ph_get_regnames`). So, we have to scan through the associated family
      # and try to see if we can guess the right version of those registers.
      for r1_info, r2_info in itertools.product(family1, family2):
        f_reg_name1, f_reg_offset1, f_reg_size1 = r1_info
        f_reg_name2, f_reg_offset2, f_reg_size2 = r2_info

        if f_reg_offset1 or f_reg_offset2:
          continue

        if ty_size == (f_reg_size1 + f_reg_size2):
          found = True
          reg_name1 = f_reg_name1
          reg_name2 = f_reg_name2

          ty1 = ty.extract(arch, 0, f_reg_size1)
          ty2 = ty.extract(arch, f_reg_size1, f_reg_size2)
          break

      if not found:
        raise Exception()

    except Exception as e:
      reg_name1 = (ida_idp.get_reg_name(argloc.reg1(), ty_size) or reg_name1).upper()
      reg_name2 = (ida_idp.get_reg_name(argloc.reg2(), ty_size) or reg_name2).upper()

    loc1 = Location()
    loc1.set_register(reg_name1)
    loc1.set_type(ty1)
    out_locs.append(loc1)

    loc2 = Location()
    loc2.set_register(reg_name2)
    loc2.set_type(ty2)
    out_locs.append(loc2)

  # Memory location computed as value in a register, plus an offset.
  #
  # TODO(pag): How does this work if the register itself is not
  #            treated as an argument?
  elif where == ida_typeinf.ALOC_RREL:
    rrel = argloc.get_rrel()
    loc = Location()
    loc.set_memory(
        _get_address_sized_reg(arch, reg_names[rrel.reg].upper()),
        rrel.off)
    loc.set_type(ty)
    out_locs.append(loc)

  # Global variable with a fixed address. We can represent this
  # as computing a PC-relative memory address.
  elif where == ida_typeinf.ALOC_STATIC:
    loc = Location()
    loc.set_memory(arch.program_counter_name(),
                   argloc.get_ea() - ea)
    loc.set_type(ty)
    out_locs.append(loc)

  # Unsupported.
  else:
    raise InvalidLocationException(
        "Unsupported location {} with type {}".format(
            str(argloc), ty.serialize(arch, {})))


def _find_segment_containing_ea(ea, seg_ref):
  """Find and return a `segment_t` containing `ea`, or `None`."""
  seg = seg_ref[0]
  if seg and seg.contains(ea):
    return seg

  seg = ida_segment.get_first_seg()
  while seg:
    seg_ref[0] = seg
    if seg.contains(ea):
      return seg
    seg = ida_segment.get_next_seg(seg.start_ea)

  return None


def _is_executable_seg(seg):
  """Returns `True` a segment's data is executable."""
  return 0 != (seg.perm & ida_segment.SEGPERM_EXEC)


def _try_map_byte(memory, ea, seg_ref):
  """Try to map a byte into memory."""
  seg = _find_segment_containing_ea(ea, seg_ref)
  if not seg:
    return False

  can_read = 0 != (seg.perm & ida_segment.SEGPERM_READ)
  if not can_read:
    return False

  can_write = 0 != (seg.perm & ida_segment.SEGPERM_WRITE)
  can_exec = 0 != (seg.perm & ida_segment.SEGPERM_EXEC)

  val = 0
  if ida_bytes.has_value(ida_bytes.get_full_flags(ea)):
    val = ida_bytes.get_wide_byte(ea) & 0xFF

  flags = ida_bytes.get_full_flags(ea)
  memory.map_byte(ea, val, can_write, can_exec)
  return True


def _get_function_bounds(func, seg_ref):
  """Get the bounds of the function containing `ea`. We want to discover jump
  table targets that are missed by IDA, and it's possible that they aren't
  marked as being part of the current function, and perhaps are after the
  assumed range of the current function. Ideally they will fall before the
  beginning of the next function, though.

  We need to be pretty careful with the case that one function tail-calls
  another. IDA will sometimes treat the end of the tail-called function
  (e.g. a thunk) as if it is the end of the caller. For this reason, we start
  with loose bounds using the prev/next functions, then try to narrow with
  the bounds of the function containing `ea`.

  NOTE(pag): This does not handle function chunks.
  """
  ea = func.start_ea
  seg = _find_segment_containing_ea(ea, seg_ref)
  if not seg:
    return ea, ea

  seg_start, seg_end = seg.start_ea, seg.end_ea
  min_ea = seg_start
  max_ea = seg_end

  if not _is_executable_seg(seg):
    return ea, ea

  # Get an upper bound using the next function.
  has_upper = False
  next_func = ida_funcs.get_next_func(ea)
  if next_func:
    next_func_seg = _find_segment_containing_ea(next_func.start_ea, seg_ref)
    if next_func_seg and _is_executable_seg(next_func_seg):
      max_ea = min(next_func.start_ea, max_ea)
      has_upper = True

  # Get a lower bound using the previous function.
  has_lower = False
  prev_func = ida_funcs.get_prev_func(ea)
  if prev_func:
    prev_func_seg = _find_segment_containing_ea(prev_func.start_ea, seg_ref)
    if prev_func_seg and _is_executable_seg(prev_func_seg):
      min_ea = max(prev_func.end_ea, min_ea)
      has_lower = True

  # Try to tighten the bounds using the function containing `ea`.
  if not has_lower:
    min_ea = max(min_ea, func.start_ea)

  if not has_upper:
    max_ea = min(max_ea, func.end_ea)

  return min_ea, max_ea


def _xref_generator(ea, get_first, get_next):
  """Generate the cross-references addresses using functors `get_first` and
  `get_next`."""
  target_ea = get_first(ea)
  while target_ea != ida_idaapi.BADADDR:
    yield target_ea
    target_ea = get_next(ea, target_ea)


def _collect_xrefs_from_func(pfn, ea, out_ref_eas):
  """Collect cross-references at `ea` in `pfn` that target code/data
  outside of `pfn`. Save them into `out_ref_eas`."""
  for ref_ea in _xref_generator(ea, ida_xref.get_first_cref_from, \
                                ida_xref.get_next_cref_from):
    if not ida_funcs.func_contains(pfn, ref_ea):
      out_ref_eas.add(ref_ea)

  for ref_ea in _xref_generator(ea, ida_xref.get_first_dref_from, \
                                ida_xref.get_next_dref_from):
    if not ida_funcs.func_contains(pfn, ref_ea):
      out_ref_eas.add(ref_ea)


class IDAFunction(Function):
  def __init__(self, arch, address, param_list, ret_list, ida_func):
    super(IDAFunction, self).__init__(arch, address, param_list, ret_list)
    self._pfn = ida_func

  def name(self):
    ea = self.address()
    try:
      flags = ida_bytes.get_full_flags(ea)
      if ida_bytes.has_name(flags):
        return ida_funcs.get_func_name(ea)
    except:
      pass
    return ""

  def visit(self, program, is_definition):
    if not is_definition:
      return

    memory = program.memory()

    seg = [None]

    ref_eas = set()
    
    # Map the continuous range of bytes associated with the main body of the
    # function. We might get a bit beyond that, as our function bounds stuff
    # looks for previous and next function locations.
    ea, max_ea = _get_function_bounds(self._pfn, seg)
    while ea < max_ea:
      if not _try_map_byte(memory, ea, seg):
        break
      _collect_xrefs_from_func(self._pfn, ea, ref_eas)
      ea += 1

    # Map the bytes of function chunks. These are discontinuous parts of a
    # function, e.g. cold code put off the critical path to reduce icache
    # pressure.
    fti = ida_funcs.func_tail_iterator_t(self._pfn)
    ok = fti.first()
    while ok:
      chunk = fti.chunk()
      ea = chunk.start_ea
      max_ea = chunk.end_ea
      while ea < max_ea:
        if not _try_map_byte(memory, ea, seg):
          break
        _collect_xrefs_from_func(self._pfn, ea, ref_eas)
        ea += 1

      ok = fti.next()

    # Now go and inspect cross-referenced date/code, and add it to the program.
    for ref_ea in ref_eas:
      try:
        program.add_function_declaration(ref_ea)
      except InvalidFunctionException:
        program.add_variable_declaration(ref_ea)

      # TODO(pag): Global variables.
      # TODO(pag): Other memory, e.g. read-only, non-global vars.


class IDAVariable(Variable):
  def __init__(self, arch, address, type_, ida_seg):
    super(IDAVariable, self).__init__(arch, address, type_)
    self._ida_seg = ida_seg

  def name(self):
    ea = self.address()
    try:
      flags = ida_bytes.get_full_flags(ea)
      if ida_bytes.has_name(flags):
        return ida_name.get_ea_name(ea)
    except:
      pass
    return ""

  def visit(self, program, is_definition):
    if not is_definition:
      return

    memory = program.memory()
    # TODO

class IDAProgram(Program):
  def __init__(self, *args):
    super(IDAProgram, self).__init__(_get_arch(), _get_os())
    self._functions = weakref.WeakValueDictionary()
    self._variables = weakref.WeakValueDictionary()

  def get_variable(self, address):
    """Given an address, return a `Variable` instance, or
    raise an `InvalidVariableException` exception."""
    if address in self._variables:
      return self._variables[address]

    arch = self._arch

    seg_ref = [None]
    if not _find_segment_containing_ea(address, seg_ref):
      raise InvalidVariableException(
          "No variable defined at or containing address {:x}".format(address))

    seg = seg_ref[0]

    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, address):
      ida_typeinf.guess_tinfo(tif, address)

    # Try to handle a variable type, otherwise make it big and empty.
    try:
      var_type = get_type(tif)
    except UnhandledTypeException as e:
      # TODO(pag): Make it a big empty array type? (especially if it's in .bss)
      raise InvalidVariableException(
          "Could not assign type to function at address {:x}: {}".format(
              address, str(e)))

    var = IDAVariable(arch, address, var_type, seg)
    self._variables[address] = var
    return var


  def get_function(self, address):
    """Given an address, return a `Function` instance or
    raise an `InvalidFunctionException` exception."""
    arch = self._arch

    pfn = ida_funcs.get_func(address)
    if not pfn:
      pfn = ida_funcs.get_prev_func(address)

    # Check this function.
    if not pfn or not ida_funcs.func_contains(pfn, address):
      raise InvalidFunctionException(
          "No function defined at or containing address {:x}".format(address))

    # Reset to the start of the function, and get the type of the function.
    address = pfn.start_ea
    if address in self._functions:
      return self._functions[address]
    
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, address):
      ida_typeinf.guess_tinfo(tif, address)

    if not tif.is_func():
      raise InvalidFunctionException(
          "Type information at address {:x} is not a function: {}".format(
              address, tif.dstr()))

    ftd = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(ftd):
      raise InvalidFunctionException(
          "Could not get function details for function at address {:x}".format(address))

    # Make sure we can handle the basic signature of the function. This might
    # not be the final signature that we go with, but it's a good way to make
    # sure we can handle the relevant types.
    try:
      func_type = get_type(tif)
    except UnhandledTypeException as e:
      raise InvalidFunctionException(
          "Could not assign type to function at address {:x}: {}".format(
              address, str(e)))

    # Go look into each of the parameters and their types. Each parameter may
    # refer to multiple locations, so we want to split each of those locations
    # into unique 
    i = 0
    max_i = ftd.size()
    param_list = []
    while i < max_i:
      funcarg = ftd[i]
      i += 1

      arg_type = get_type(funcarg.type)
      arg_type_str = arg_type.serialize(arch, {})

      j = len(param_list)
      _expand_locations(arch, pfn, arg_type, funcarg.argloc, param_list)
      
      # If we have a parameter name, then give a name to each of the expanded
      # locations associated with this parameter.
      if funcarg.name:
        if (j + 1) == len(param_list):
          param_list[-1].set_name(funcarg.name)
        else:
          k = j
          while k < len(param_list):
            param_list[-1].set_name("{}_{}".format(funcarg.name, k - j))
            k += 1

    # Build up the list of return values.
    ret_list = []
    ret_type = get_type(ftd.rettype)
    if not isinstance(ret_type, VoidType):
      _expand_locations(arch, pfn, ret_type, ftd.retloc, ret_list)

    func = IDAFunction(arch, address, param_list, ret_list, pfn)
    self._functions[address] = func
    return func


_PROGRAM = None

def get_program(*args, **kargs):
  global _PROGRAM
  if _PROGRAM:
    return _PROGRAM

  _PROGRAM = IDAProgram()
  return _PROGRAM

