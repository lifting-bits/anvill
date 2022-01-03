#
# Copyright (c) 2019-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(pure_lib_dest "${CMAKE_INSTALL_PREFIX}/lib/python3.8/dist-packages")

# Redirect the whole installation if DESTDIR is specified
if(DEFINED ENV{DESTDIR})
  set(root_parameter "--root=$ENV{DESTDIR}")
  set(single_version "--single-version-externally-managed")
endif()

# and if we *are* in a virtualenv, default to normal install to install into venv
# otherwise, if *NO VENV* or we have a DESTDIR, set up the prefixes
if((NOT DEFINED ENV{VIRTUAL_ENV}) OR (DEFINED ENV{DESTDIR}))
  set(purelib_arg "--install-purelib=${pure_lib_dest}")
  set(prefix_arg "--prefix=${CMAKE_INSTALL_PREFIX}")
endif()

execute_process(
  COMMAND
    "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_LIST_DIR}/../../setup.py"
    install
    ${purelib_arg}
    ${prefix_arg}
    ${root_parameter}
    ${single_version}
  RESULT_VARIABLE setup_py_result
  OUTPUT_VARIABLE setup_py_stdout
  ERROR_VARIABLE setup_py_stderr
)

message(STATUS "${setup_py_stdout}")

if(NOT ${setup_py_result} EQUAL 0)
  message(FATAL_ERROR "result: ${setup_py_result}\n\n"
                      "stderr: ${setup_py_stderr}"
  )
endif()
