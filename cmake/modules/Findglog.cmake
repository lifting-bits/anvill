include("${CMAKE_CURRENT_LIST_DIR}/utils.cmake")

set(ANVILL_GLOG_LOCATION "/usr" CACHE FILEPATH "glog install directory")

set(glog_library_list
  "glog"
)

message(STATUS "Attempting to locate: glog (hints: ANVILL_GLOG_LOCATION=\"${ANVILL_GLOG_LOCATION}\")")

locateLibrary(
  NAME "glog"
  HINT "${ANVILL_GLOG_LOCATION}"
  LIBRARIES ${glog_library_list}
  MAIN_INCLUDE "glog/logging.h"
)
