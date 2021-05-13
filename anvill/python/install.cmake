#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(pure_lib_dest "${CMAKE_INSTALL_PREFIX}/lib/python3/dist-packages")

# Only redirect installation if DESTDIR is specified, otherwise just do a normal "setup.py install"
if(DEFINED ENV{DESTDIR})
  set(package_parameters 
    "--single-version-externally-managed"
    "--prefix=${CMAKE_INSTALL_PREFIX}"
    "--root=$ENV{DESTDIR}"
    "--install-purelib=${pure_lib_dest}"
    )
endif()

execute_process(
  COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/../../setup.py" install ${package_parameters}
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
