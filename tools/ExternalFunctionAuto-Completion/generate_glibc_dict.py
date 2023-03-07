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

# this file is based on the https://github.com/lifting-bits/mcsema project
# mcsema/mcsema/OS/Linux/generate_abi_wrapper.py 
# the original script have some bugs, and can't solve the Name Mangling problem.
# this scipt is part of the External Function auto-completion, it's goal is to loop 
# over the AST tree of given head file, and generate a dict that can be used for the auto-completion
from encodings import utf_8
import imp
import os
import re
from pickle import TRUE
import sys
import argparse
import logging
from collections import defaultdict



cc_path = os.environ['CLANG_EXE']
cclib_path = os.environ['CLANG_LIB']
assert cc_path, "Please specify environment variable 'CLANG_EXE' with path to clang executable"

try:
  import ccsyspath
  syspath = ccsyspath.system_include_paths(cc_path)
  print(syspath)
except ImportError:
  syspath = list()


SUPPORTED_ARCH = ["x86", "amd64"]

SUPPORTED_LIBRARY_TYPE = ["c", "cpp"]

ARCH_NAME = ""

ABI_LIBRARY_TYPE = ""

logging.basicConfig(filename="debug.log",level=logging.DEBUG)

py_header1 = """
class dict:
  dictionary={

"""
py_end1 = """
  }

"""

#The list saves the parsed functions
FUNCDECL_LIST = defaultdict(list)


UNSUPPORTED_FUNC = ["__isoc99_fscanf", "__isoc99_scanf","__isoc99_sscanf","__isoc99_vfscanf","__isoc99_vscanf","__isoc99_vsscanf",
"__isoc99_fwscanf","__isoc99_wscanf","__isoc99_swscanf","__isoc99_vfwscanf","__isoc99_vswscanf",
"__xpg_strerror_r","__xpg_sigpause"]

LOCAL_HEADERS = []

# Process the function types and remove the `__attribute__((...))` identifier
# from the function types
def process_function_types(type_string):
  """ Pre-process the function types for the Funcdecl
  """
  split_string = type_string.split(' ')
  return ' '.join(str for str in split_string if '__attribute__' not in str)

def get_function_pointer(type_string):
  """ convert the function types to the pointer type
  """
  return type_string[0:type_string.find('(')]
  #return type_string[0:type_string.find('(')-1] + " (*)" + type_string[type_string.find('('):]

def is_valid_type(type_string):
  if "_Complex" in type_string or 'typeof' in type_string:
    return False
  else:
    return True

def is_blacklisted_func(func_name):
  if 'operator' in func_name:
    return True
  return False

def visit_func_decl(node):
  """ Visit the function decl node and create a map of
      function name with the mangled name
  """
  try:
    from clang.cindex import CursorKind, TypeKind,LinkageKind

  except ImportError:
    return
  #Here, traverse the nodes in the AST tree and find FUNCTION_DECL, which is the function node
  if node.kind == CursorKind.FUNCTION_DECL:
    func_name = node.spelling
    node.result_type.spelling
    mangled_name = node.spelling
    parameters_obj=re.search('[(].*[)]',node.displayname)
    parameters=parameters_obj.string[parameters_obj.regs[0][0]:parameters_obj.regs[0][1]]

      
    if not is_blacklisted_func(mangled_name):
      func_type = process_function_types(node.type.spelling)
      if is_valid_type(func_type):
               
        key=mangled_name
        FUNCDECL_LIST[key].append([mangled_name,node.result_type.spelling,parameters])
      else:
        FUNCDECL_LIST[func_name].append([mangled_name, 'void *', node.location,func_name])


  #recursive deep traversal
  for i in node.get_children():
    visit_func_decl(i)



def write_cc_file(hfile, outfile):
  """ Generate ABI library source for the c headers; 
  """

  # generate the abi lib cc file
  with open(outfile, "w") as s:
    s.write(py_header1)
    #The first layer of loops traverses FUNCDECL_LIST
    for key in FUNCDECL_LIST.keys():
      type_values = FUNCDECL_LIST[key]
      #The second layer of loop, get the function name
      for type in type_values:      
      #type[0,1,2] points to [mangled_name, node.result_type.spelling, parameters]
        s.write("\"{0}\":\"{1}\",\n".format(type[0],type[1]))
        #Finish writing "(void *) cos"
    
    s.write(py_end1)

    print("Number of functions: {}".format(len(FUNCDECL_LIST)))
    
def write_cxx_file(hfile, outfile):
  """ Generate ABI library source for the cxx headers; 
  """

  # generate the abi lib cc file
  with open(outfile, "w") as s:
    s.write(py_header1)
    #The first layer of loops traverses FUNCDECL_LIST
    for key in FUNCDECL_LIST.keys():
      type_values = FUNCDECL_LIST[key]
      #The second layer of loop, get the function name
      #some funcs may have mutiple returns, we use a list to store all the returns with it's params
      if len(type_values)!=1:
        num=1
        s.write("\"{0}\":[".format(key))
        for func in type_values:
          #func[0,1,2] points to [mangled_name, node.result_type.spelling, parameters]
          s.write("(\"{0}\",\"{1}\")".format(func[1],func[2]))
          if num !=len(type_values):
            s.write(",")
            num=num+1
        s.write("],\n")
      else:
        for type in type_values:      
        #type[0,1,2] points to [mangled_name, node.result_type.spelling, parameters]
          s.write("\"{0}\":\"{1}\",\n".format(type[0],type[1]))
          
    s.write(py_end1)

    print("Number of functions: {}".format(len(FUNCDECL_LIST)))



def write_library_file(hfile, outfile):
  """ Generate the library files """
  try:
    import clang.cindex
    from clang.cindex import Config
    Config.get_filename(Config)
    Config.set_library_file(cclib_path)
    #Config.set_library_file("/usr/lib/llvm-11/lib/libclang-11.so.1")
    cc_index = clang.cindex.Index.create()
    Config.get_filename(Config)
    libc_type = 'c++' if ABI_LIBRARY_TYPE == "cpp" else 'c'
      #tu is the parsed AST tree
      #Switch here to use c or c++ analysis
      #The default is -m64
    tu = cc_index.parse(hfile, args=['-x', libc_type, '-m64'])


    #else:
      #print("Unsupported architecture")

    print(tu.diagnostics)
    visit_func_decl(tu.cursor)

  except ImportErro:
    libc_type = 'c++' if ABI_LIBRARY_TYPE == "cpp" else 'c'
    pass

  if libc_type == 'c':
    write_cc_file(hfile, outfile)
  elif libc_type == 'c++':
    write_cxx_file(hfile, outfile)


  
def parse_headers(infile, outfile):

    write_library_file(infile, outfile)


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  
  #parser.add_argument(
    #'--arch',
    #help='Name of the architecture.',
    #required=True)
  
  parser.add_argument(
    '--type',
    help='ABI Library types c/c++.',
    required=True)

  parser.add_argument(
    "--input",
    help="The input pre-processed header file",
    required=True)
  
  parser.add_argument(
    "--output",
    help="The output file generated with the script",
    required=True)
  
  args = parser.parse_args(args=sys.argv[1:])
  
  #ARCH_NAME = args.arch
  #if ARCH_NAME not in SUPPORTED_ARCH:
    #logger.debug("Arch {} is not supported!".format(args.arch))
    
  ABI_LIBRARY_TYPE = args.type
  if ABI_LIBRARY_TYPE not in SUPPORTED_LIBRARY_TYPE:
    logger.debug("Library type {} not supported!".format(args.type))

  res = bytes(os.path.dirname(os.path.abspath(args.input)), 'utf-8')
  syspath.append(res)
  parse_headers(args.input, args.output)
