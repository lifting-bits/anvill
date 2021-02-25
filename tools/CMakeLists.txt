#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

function(checkForLLVMJsonSupport output_variable)
  set(test_file_path "${CMAKE_CURRENT_BINARY_DIR}/llvm_json_support_test.cpp")

  file(WRITE
    "${test_file_path}"

    "#include <llvm/Support/JSON.h>\n"
    "int main() { return 0; }\n"
  )

  try_compile(
    ANVILL_LLVM_SUPPORTS_JSON
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${test_file_path}"
    LINK_LIBRARIES remill
  )

  set("${output_variable}" ${ANVILL_LLVM_SUPPORTS_JSON} PARENT_SCOPE)
endfunction()

checkForLLVMJsonSupport("ANVILL_LLVM_SUPPORTS_JSON")
if(ANVILL_LLVM_SUPPORTS_JSON)
  message(STATUS "anvill: LLVM JSON support was found, enabling targets: anvill-decompile-json, anvill-specify-bitcode")

  add_subdirectory("decompile-json")
  add_subdirectory("specify-bitcode")

else()
  message(STATUS "anvill: LLVM JSON support was not found, disabling targets: anvill-decompile-json, anvill-specify-bitcode")
endif()
