

try:
  from elftools.elf.elffile import ELFFile
except ImportError:
  print "Install pyelf tools"
  
  
class Dwarf(object):
  def __init__(self, in_file):
    f = open(in_file, 'rb')
    self._felf = ELFFile(f)

  def has_dwarf_info(self):
    return self._felf.has_dwarf_info()

  def print_compile_units(self):
    dwarf_info = self._felf.get_dwarf_info()
    print "print_compile_units"
    for cu in dwarf_info.iter_CUs():
      print 'Found a compile unit at offset {0}, length {1}'.format(cu.cu_offset, cu['unit_length'])