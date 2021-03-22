include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

set(ANVILL_XED_LOCATION "/usr" CACHE FILEPATH "XED install directory")

set(xed_library_list
  "xed"
  "xed-ild"
)

message(STATUS "Attempting to locate: XED (hints: ANVILL_XED_LOCATION=\"${ANVILL_XED_LOCATION}\")")

locateLibrary(
  NAME "xed"
  HINT "${ANVILL_XED_LOCATION}"
  LIBRARIES ${xed_library_list}
  MAIN_INCLUDE "xed/xed-decode.h"
)
