#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_test(NAME anvill_test_roundtrip
  COMMAND "/usr/bin/env" "PYTHONPATH=${PROJECT_SOURCE_DIR}/anvill/python:$ENV{PYTHONPATH}" "${CMAKE_CURRENT_SOURCE_DIR}/scripts/roundtrip.py" "$<TARGET_FILE:anvill-decompile-json>" "${CMAKE_CURRENT_SOURCE_DIR}/cases" "${CMAKE_C_COMPILER}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_test(NAME anvill_test_ret0
  COMMAND "$<TARGET_FILE:anvill-decompile-json>" -spec "${CMAKE_CURRENT_SOURCE_DIR}/specs/ret0.json" -bc_out "${CMAKE_CURRENT_BINARY_DIR}/ret0.bc" -ir_out "${CMAKE_CURRENT_BINARY_DIR}/ret0.ir"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_test(NAME anvill_test_jmp_ret0
  COMMAND "$<TARGET_FILE:anvill-decompile-json>" -spec "${CMAKE_CURRENT_SOURCE_DIR}/specs/jmp_ret0.json" -bc_out "${CMAKE_CURRENT_BINARY_DIR}/jmp_ret0.bc" -ir_out "${CMAKE_CURRENT_BINARY_DIR}/jmp_ret0.ir"
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)