add_library(llvm_utils
  include/llvm_utils/TypeParser.h
  src/TypeParser.cpp

  include/llvm_utils/TypePrinter.h
  src/TypePrinter.cpp

  include/llvm_utils/Utils.h
  src/Utils.cpp
)

target_include_directories(llvm_utils PUBLIC
  include
)

target_link_libraries(llvm_utils PUBLIC
  remill
)