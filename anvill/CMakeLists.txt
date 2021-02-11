#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

add_library(anvill STATIC
  include/anvill/Type.h

  lib/Arch/AArch64_C.cpp
  lib/Arch/SPARC32_C.cpp
  lib/Arch/SPARC64_C.cpp
  lib/Arch/X86_C.cpp
  lib/Arch/X86_FastCall.cpp
  lib/Arch/X86_StdCall.cpp
  lib/Arch/X86_ThisCall.cpp
  lib/Arch/X86_64_SysV.cpp

  lib/Arch/AllocationState.h
  lib/Arch/AllocationState.cpp

  lib/Arch/Arch.h
  lib/Arch/Arch.cpp

  include/anvill/TypeParser.h
  lib/TypeParser.cpp

  include/anvill/TypePrinter.h
  lib/TypePrinter.cpp

  include/anvill/Program.h
  lib/Program.cpp
  
  include/anvill/RecoverMemRefs.h
  lib/RecoverMemRefs.cpp

  include/anvill/Decl.h
  lib/Decl.cpp

  include/anvill/Lift.h
  lib/Lift.cpp

  include/anvill/MCToIRLifter.h
  lib/MCToIRLifter.cpp

  include/anvill/Optimize.h
  lib/Optimize.cpp

  include/anvill/Analyze.h
  lib/Analyze.cpp

  include/anvill/Util.h
  lib/Util.cpp
)

appendRemillVersionToTargetOutputName(anvill)

target_include_directories(anvill PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(anvill PUBLIC remill_settings remill AnvillVersion)

macro(target_public_headers TARGET)
  set_target_properties(${TARGET} PROPERTIES PUBLIC_HEADER "${ARGN}")
endmacro()

target_public_headers(anvill
  include/anvill/Analyze.h
  include/anvill/Decl.h
  include/anvill/Lift.h
  include/anvill/Optimize.h
  include/anvill/Program.h
  include/anvill/RecoverMemRefs.h
  include/anvill/Type.h
  include/anvill/TypeParser.h
  include/anvill/TypePrinter.h
  include/anvill/Version.h
  include/anvill/Util.h
)
