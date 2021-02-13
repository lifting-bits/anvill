# Based on: https://github.com/andrew-hardin/cmake-git-version-tracking/blob/master/better-example/CMakeLists.txt
# By Andrew Hardin
# Released under the MIT License.
# https://raw.githubusercontent.com/andrew-hardin/cmake-git-version-tracking/master/LICENSE
#
# Define the two required variables before including
# the source code for watching a git repository.

function(generateAnvillVersionLibrary)
  set(PRE_CONFIGURE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/Version.cpp.in")
  set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/Version.cpp")
  set(GIT_WORKING_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/git_watcher.cmake")

  set(Version_PUBLIC_H
    "${CMAKE_CURRENT_SOURCE_DIR}/include/anvill/Version.h"
  )

  # Create a library out of the compiled post-configure file.
  add_library(anvill_version STATIC
    ${POST_CONFIGURE_FILE}
    ${Version_PUBLIC_H}
  )

  # Needed for compilation settings
  target_link_libraries(anvill_version PRIVATE
    remill_settings
  )

  target_include_directories(anvill_version PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  )

  add_dependencies(anvill_version check_git_anvill)

  if(ANVILL_ENABLE_INSTALL_TARGET)
    install(
      TARGETS anvill_version
      EXPORT anvillTargets
    )
  endif()
endfunction()

generateAnvillVersionLibrary()
