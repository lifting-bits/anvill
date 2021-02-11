#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

# Find remill first because its config has useful dependency-finding info that
# needs to be found before the CMake `project` declaration
find_package(remill COMPONENTS VCPKG_DEPS QUIET)
include(cmake/vcpkg_helper.cmake)

project(anvill)
cmake_minimum_required(VERSION 3.14)

include("cmake/options.cmake")
include("cmake/settings.cmake")
include("cmake/utils.cmake")

include(GNUInstallDirs)

if(ANVILL_ENABLE_TESTS)
  enable_testing()
endif()

FindAndSelectClangCompiler()

find_package(remill CONFIG REQUIRED)

add_subdirectory("libraries")
add_subdirectory("tools")
add_subdirectory("anvill")



#
# tool target settings
#









configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/anvillConfig_vcpkg.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
  @ONLY
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/anvillConfig.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/anvill"
)

install(EXPORT anvillTargets
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/anvill")

function(generateAnvillInstallTarget)
  if(NOT ANVILL_ENABLE_INSTALL_TARGET)
    return()
  endif()

  #
  # Native components
  #

  # Depending on the LLVM version used, some targets may not
  # be available
  set(install_target_list
    anvill
  )

  if(TARGET anvill-decompile-json)
    list(APPEND install_target_list
      anvill-decompile-json
    )
  endif()

  if(TARGET anvill-specify-bitcode)
    list(APPEND install_target_list
      anvill-specify-bitcode
    )
  endif()

  install(
    TARGETS
      ${install_target_list}

    EXPORT
      anvillTargets

    LIBRARY DESTINATION
      lib

    ARCHIVE DESTINATION
      lib

    RUNTIME DESTINATION
      bin

    INCLUDES DESTINATION
      include
  )

  #
  # Python components
  #

  set(ANVILL_PYTHON_SOURCES
    setup.py
    python/anvill/__init__.py
    python/anvill/__main__.py
    python/anvill/arch.py
    python/anvill/binja.py
    python/anvill/exc.py
    python/anvill/function.py
    python/anvill/ida.py
    python/anvill/loc.py
    python/anvill/mem.py
    python/anvill/os.py
    python/anvill/program.py
    python/anvill/type.py
    python/anvill/var.py
  )

  if(NOT DEFINED ENV{VIRTUAL_ENV})
    # NOT a venv install, specify --user and --prefix
    set(extra_install_flags --force --user --prefix=)
  else()
    # virtual env; install normally
    set(extra_install_flags "")
  endif()

  if(ANVILL_INSTALL_PYTHON2_LIBS)
    add_custom_target(install_anvill_python2
      DEPENDS ${ANVILL_PYTHON_SOURCES})

    add_custom_command(
      TARGET install_anvill_python2 POST_BUILD
      COMMAND which python2 && python2 setup.py install ${extra_install_flags}
      COMMENT "Installing Anvill Python 2 API"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

    add_dependencies(anvill
      install_anvill_python2
    )
  endif()

  if(ANVILL_INSTALL_PYTHON3_LIBS)
    add_custom_target(install_anvill_python3
      DEPENDS ${ANVILL_PYTHON_SOURCES})

    add_custom_command(
      TARGET install_anvill_python3 POST_BUILD
      COMMAND which python3 && python3 setup.py install ${extra_install_flags}
      COMMENT "Installing Anvill Python 3 API"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

    add_dependencies(anvill
      install_anvill_python3
    )
  endif()

  #
  # anvill-decompile-json tests
  #

  set(roundtrip_script_path 
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/decompile-json/tests/scripts/roundtrip.py"
  )

  install(
    FILES "${roundtrip_script_path}"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/anvill"
  )

#NOTE(artem): Uncomment and add tests as we pass them
set(ROUNDTRIP_TEST_FILES
tests/array_swap.c
# tests/assert.c
tests/binops.c
tests/bitops.c
# tests/branch.c
tests/cast.c
# tests/funcptr.c
tests/init_list.c
tests/inttoptr.c
# tests/loop.c
# tests/nested_struct.c
tests/nullptr.c
tests/ret0.c
tests/struct_swap.c
tests/struct.c
# tests/sum.c
tests/trunc.c
tests/zeroinit.c
tests/zext.c
# tests/binja_var_none_type.c
)

install(
FILES ${ROUNDTRIP_TEST_FILES}
DESTINATION "${CMAKE_INSTALL_DATADIR}/anvill/tests")
endfunction()

generateAnvillInstallTarget()
