#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_executable(anvill-decompile-json
  src/main.cpp
)

target_link_libraries(anvill-decompile-json PRIVATE
  anvill
)

appendRemillVersionToTargetOutputName(anvill-decompile-json)

if(ANVILL_ENABLE_TESTS)
  add_subdirectory("tests")
endif()

if(ANVILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS
      anvill-decompile-json

    EXPORT
      anvillTargets

    RUNTIME DESTINATION
      bin
  )

  #
  # anvill-decompile-json tests
  #

  set(roundtrip_script_path 
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/roundtrip.py"
  )

  install(
    FILES "${roundtrip_script_path}"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/anvill"
  )

  # NOTE(artem): Uncomment and add tests as we pass them
  set(ROUNDTRIP_TEST_FILES
    tests/samples/array_swap.c
    tests/samples/binops.c
    tests/samples/bitops.c
    tests/samples/cast.c
    tests/samples/init_list.c
    tests/samples/inttoptr.c
    tests/samples/nullptr.c
    tests/samples/ret0.c
    tests/samples/struct_swap.c
    tests/samples/struct.c
    tests/samples/trunc.c
    tests/samples/zeroinit.c
    tests/samples/zext.c

    # tests/assert.c
    # tests/branch.c
    # tests/funcptr.c
    # tests/loop.c
    # tests/nested_struct.c
    # tests/sum.c
    # tests/binja_var_none_type.c
  )

  install(
    FILES ${ROUNDTRIP_TEST_FILES}
    DESTINATION "${CMAKE_INSTALL_DATADIR}/anvill/tests"
  )
endif()
