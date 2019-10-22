

import json
import logging
import argparse
import magic
import binaryninja as binja

LOGNAME = 'binary.log'
log = logging.getLogger(LOGNAME)

_TYPE_MAP= {
  'int8_t'  : 'b',
  'uint8_t' : 'B',
  'int16_t' : 'h',
  'uint16_t': 'H',
  'int32_t' : 'i',
  'uint32_t': 'I',
  'long'    : 'l',
  'ulong'   : 'L',
  'void'    : 'v',
  'const* void' : '*v',
  'void* const' : '*v'
}

# Utility functions
def read_bytes_slowly(bv, offset, length):
  br = binja.BinaryReader(bv)
  bytestr = []
  for x in xrange(offset, offset+length):
    br.seek(x)
    bytestr.append('{:x}'.format(br.read8()))
  return ''.join(bytestr)

# Utility wrappers
def address(addr):
  return addr

class XRef(object):
  IMMEDIATE = 0
  MEMORY = 1
  DISPLACEMENT = 2
  CONTROLFLOW = 3

  def __init__(self, addr, reftype, mask=0):
    self.addr = addr
    self.type = reftype
    self.mask = mask

  def __hash__(self):
    return hash((self.addr, self.type))

class BasicBlock(object):
  def __init__(self, bv, func, bb):
    self._bv = bv
    self._func = func
    self._bb = bb
    self.get_xrefs()

  def get_xrefs(self):
    instrs = list(self._bb.disassembly_text)
    for insn in instrs:
      il_insn = self._func.get_lifted_il_at(insn.address)

  def get_bytes_raw(self):
    offset = self._bb.start
    length = self._bb.end - self._bb.start
    bytes = read_bytes_slowly(self._bv, offset, length)
    return bytes

class Function(object):
  def __init__(self, bv, func):
    self._bv = bv
    self._func = func
    self._cc = func.calling_convention
    self._arch = func.calling_convention.arch
    self._json_object = {}
    self._json_object['name'] = func.name
    self._json_object['address'] = address(func.start)
    self._json_object['parameters'] = self.get_params()
    self._json_object['return_address'] = self.get_return_address()
    self._json_object['return_values'] = self.get_return_registers()

  def get_params(self):
    param_list = []
    index = 0
    param_regs = self._cc.int_arg_regs
    for var in self._func.parameter_vars:
      param = {}
      param['name'] = str(var)
      param['type'] = _TYPE_MAP[str(var.type)]
      if var.source_type == binja.VariableSourceType.RegisterVariableSourceType:
        param['register'] = param_regs[index]
      elif var.source_type == binja.VariableSourceType.StackVariableSourceType:
        stack = {}
        stack['register'] = self._bv.arch.stack_pointer
        stack['offset'] = var.storage
        param['memory'] = stack
      index = index+1
      param_list.append(param)
    return param_list

  def get_return_address(self):
    return_addr = {}
    for var in self._func.stack_layout:
      if var.name == '__return_addr' and var.source_type == binja.VariableSourceType.StackVariableSourceType:
        addr = {}
        addr['register'] = self._bv.arch.stack_pointer
        addr['offset'] = var.storage
        return_addr['memory'] = addr
        return_addr['type'] = _TYPE_MAP[str(var.type)]
    return return_addr

  def get_return_registers(self):
    regs_list = []
    for r in self._func.return_regs:
      reg = {}
      reg['register'] = r
      reg['type'] = str(self._func.return_type)
      regs_list.append(reg)
    return regs_list

  def get_function_raw(self):
    return '\x00'

  def get_json_object(self):
    return self._json_object

class Segment(object):
  def __init__(self, bv):
    self._bv = bv

def get_stack_info(bv):
  stack = {}
  if bv.arch.name == 'x86_64':
    stack['address'] = address(0x7ffeefbff000)
    stack['size'] = 0x8000
    stack['start_offset'] = 0x1000
  return stack

def get_function_params(bv, func):
  params = []
  cc = func.calling_convention
  print func.function_type
  for var in func.parameter_vars:
    param = {}
    param['name'] = str(var)
    param['type'] = str(var.type)
    print var.storage
    params.append(param)
  return params

def get_functions(bv):
  functions = []
  for func in bv.functions:
    f_object = Function(bv, func)
    functions.append(f_object.get_json_object())
  return functions

def get_segments(bv):
  segments = []
  #for seg in bv.segments:
   # print seg
   
def get_memory(bv):
  memory_list = []
  for func in bv.functions:
    for bb in func.basic_blocks:
      bb_raw = {}
      bb_object = BasicBlock(bv, func, bb)
      seg = bv.get_segment_at(bb.start)
      bb_raw['data'] = bb_object.get_bytes_raw()
      bb_raw['address'] = address(bb.start)
      bb_raw['is_readable'] = seg.readable
      bb_raw['is_executable'] = seg.executable
      memory_list.append(bb_raw)

  for addr in bv.data_vars:
    print hex(addr)
    var = bv.get_data_var_at(addr)
    var_seg = bv.get_segment_at(addr)
    next_var = bv.get_next_data_var_after(addr)
    next_var_seg = bv.get_segment_at(next_var)
    size = next_var - var.address
    if next_var_seg and var_seg.start != next_var_seg.start:
      size = var_seg.data_end - var.address
      
    raw = {}
    raw['data'] = read_bytes_slowly(bv, var.address, size)
    raw['address'] = address(var.address)
    raw['is_readable'] = var_seg.readable
    raw['is_executable'] = var_seg.executable
    memory_list.append(raw)

  return memory_list

def load_binary(binary_path):
  magic_type = magic.from_file(binary_path)

  if 'ELF' in magic_type:
    bv_type = binja.BinaryViewType['ELF']
  elif 'PE32' in magic_type:
    bv_type = binja.BinaryViewType['PE']
  elif 'Mach-O' in magic_type:
    bv_type = binja.BinaryViewType['Mach-O']
  else:
    bv_type = binja.BinaryViewType['Raw']

  print 'Loading binary in binja... ', binary_path
  bv = bv_type.open(binary_path)
  bv.add_analysis_option("linearsweep")
  bv.update_analysis_and_wait()
  return bv

def export_bn(bv, os, outfile):
  json_array = {}
  print bv.arch.stack_pointer
  json_array['arch'] = bv.arch.name
  json_array['os'] = os
  json_array["function"] = get_functions(bv)
  json_array['memory'] = get_memory(bv)
  json_array['stack'] = get_stack_info(bv)

  with open(outfile, 'w') as outfile:
    json.dump(json_array, outfile, sort_keys=True, indent=2)

if __name__ == "__main__":
  arg_parser = argparse.ArgumentParser()

  arg_parser.add_argument(
    '--binary',
    help='Binary to recover the function informations',
    required=True)

  arg_parser.add_argument(
    '--os',
    help='Binary to recover the function informations',
    required=True)

  arg_parser.add_argument(
    '--json',
    help='Binary to recover the function informations',
    required=True)

  args = arg_parser.parse_args()
  bv = load_binary(args.binary)
  export_bn(bv, args.os, args.json)
