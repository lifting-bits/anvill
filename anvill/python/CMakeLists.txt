#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

if(ANVILL_ENABLE_INSTALL_TARGET)
  set(setup_file_path "${PROJECT_SOURCE_DIR}/setup.py")

  set(ANVILL_PYTHON_SOURCES
    "${setup_file_path}"
    anvill/__init__.py
    anvill/__main__.py
    anvill/arch.py
    anvill/binja.py
    anvill/exc.py
    anvill/function.py
    anvill/ida.py
    anvill/loc.py
    anvill/mem.py
    anvill/os.py
    anvill/program.py
    anvill/type.py
    anvill/var.py
  )

  if(NOT DEFINED ENV{VIRTUAL_ENV})
    # NOT a venv install, specify --user and --prefix
    set(extra_install_flags --force --user --prefix=)
  else()
    # virtual env; install normally
    set(extra_install_flags "")
  endif()

  if(ANVILL_INSTALL_PYTHON3_LIBS)
    add_custom_target(install_anvill_python3
      DEPENDS ${ANVILL_PYTHON_SOURCES}
    )

    add_custom_command(
      TARGET install_anvill_python3 POST_BUILD
      COMMAND which python3 && python3 "${setup_file_path}" install ${extra_install_flags}
      COMMENT "Installing Anvill Python 3 API"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )

    add_dependencies(anvill
      install_anvill_python3
    )
  endif()
endif()
