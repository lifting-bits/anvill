find_package(LLVM REQUIRED CONFIG)
set(llvm_component_list
  core
  InstCombine
  ScalarOpts
  IRReader
  BitWriter
)

llvm_map_components_to_libnames(llvm_library_list
  ${llvm_component_list}
)

add_library(thirdparty_llvm INTERFACE)
target_link_libraries(thirdparty_llvm INTERFACE
  ${llvm_library_list}
)

target_include_directories(thirdparty_llvm SYSTEM INTERFACE
  ${LLVM_INCLUDE_DIRS}
)

target_compile_definitions(thirdparty_llvm INTERFACE
  ${LLVM_DEFINITIONS}
  LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR}
  LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR}
)

# Ubuntu/Debian workaround
if(EXISTS "/usr/include/llvm-${LLVM_VERSION_MAJOR}")
  target_include_directories(thirdparty_llvm SYSTEM INTERFACE
    "/usr/include/llvm-${LLVM_VERSION_MAJOR}"
  )
endif()

# Due to the way the library exports the targets, this will not
# work
if(ANVILL_ENABLE_INSTALL_TARGET)
  message(FATAL_ERROR "System builds only work when ANVILL_ENABLE_INSTALL_TARGET is disabled")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

find_package(glog REQUIRED)
find_package(gflags REQUIRED)
find_package(XED REQUIRED)
find_package(remill REQUIRED)
