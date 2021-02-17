#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(setup_file_path "${PROJECT_SOURCE_DIR}/setup.py")

if(ANVILL_ENABLE_INSTALL_TARGET AND NOT ANVILL_INSTALL_PYTHON3_LIBS)
  install(
    FILES "${PROJECT_SOURCE_DIR}/anvill/plugins/ida/anvill.py"
    DESTINATION "share/anvill/ida"
  )

  install(CODE
    "execute_process(COMMAND ${setup_file_path} install --single-version-externally-managed --prefix=${CMAKE_INSTALL_PREFIX} --root=$ENV{DESTDIR})"
  )
endif()

if(ANVILL_INSTALL_PYTHON3_LIBS)
  message(WARNING "The ANVILL_INSTALL_PYTHON3_LIBS setting is used to auto-install "
                  "anvill to the local machine. To create redistributable packages "
                  "you only need to enable ANVILL_ENABLE_INSTALL_TARGET")

  set(frontend_source_list
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

  find_package(Python3 3.8 COMPONENTS Interpreter REQUIRED)

  set(installer_log "${CMAKE_CURRENT_BINARY_DIR}/frontend_installer_log.txt")

  add_custom_command(
    OUTPUT "${installer_log}"
    COMMAND "${Python3_EXECUTABLE}" "${setup_file_path}" install ${extra_install_flags} > "${installer_log}" 2>&1
    DEPENDS ${frontend_source_list}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Installing Anvill Python 3 API **to the local machine**. Log: ${installer_log}"
    VERBATIM
  )

  add_custom_target(frontend_installer
    DEPENDS "${installer_log}"
  )

  add_dependencies(anvill
    frontend_installer
  )
endif()
