# Based on: https://github.com/andrew-hardin/cmake-git-version-tracking/blob/master/better-example/CMakeLists.txt
# By Andrew Hardin
# Released under the MIT License.
# https://raw.githubusercontent.com/andrew-hardin/cmake-git-version-tracking/master/LICENSE
#
# Define the two required variables before including
# the source code for watching a git repository.
set(PRE_CONFIGURE_FILE "Version.cpp.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/Version.cpp")
set(GIT_WORKING_DIR "${CMAKE_PROJECT_DIR}")
include("${PROJECT_SOURCE_DIR}/cmake/git_watcher.cmake")

set(Version_PUBLIC_H
    "${PROJECT_SOURCE_DIR}/include/anvill/Version.h"
)
# Create a library out of the compiled post-configure file.
add_library(AnvillVersion STATIC
  ${POST_CONFIGURE_FILE}
  ${Version_PUBLIC_H}
  )
# Needed for compilation settings
target_link_libraries(AnvillVersion PRIVATE remill_settings)
target_include_directories(AnvillVersion PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
add_dependencies(AnvillVersion check_git_${PROJECT_NAME})
install(
  TARGETS AnvillVersion
  EXPORT anvillTargets
)
