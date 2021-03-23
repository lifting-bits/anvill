include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

set(ANVILL_REMILL_LOCATION "/usr" CACHE FILEPATH "remill install directory")

set(remill_library_list
  "remill_arch"
  "remill_arch_aarch64"
  "remill_arch_sparc64"
  "remill_bc"
  "remill_version"
  "remill_arch_aarch32"
  "remill_arch_sparc32"
  "remill_arch_x86"
  "remill_os"
)

message(STATUS "Attempting to locate: remill (hints: ANVILL_REMILL_LOCATION=\"${ANVILL_REMILL_LOCATION}\")")

locateLibrary(
  NAME "remill"
  HINT "${ANVILL_REMILL_LOCATION}"
  LIBRARIES ${remill_library_list}
  MAIN_INCLUDE "remill/Version/Version.h"
)

if(NOT DEFINED LLVM_VERSION_MAJOR)
  message(FATAL_ERROR "The LLVM_VERSION_MAJOR variable is not set")
endif()

set(REMILL_LLVM_VERSION "${LLVM_VERSION_MAJOR}")

# anvill relies on inheriting all the libraries from remill
# so we have to attach them there
add_library(remill_settings INTERFACE)

target_link_libraries(remill_settings INTERFACE
  thirdparty_llvm
  xed
  gflags
  glog
)

target_link_libraries(remill INTERFACE
  remill_settings
)

target_compile_features(remill_settings INTERFACE cxx_std_17)
