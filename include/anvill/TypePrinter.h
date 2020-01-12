#pragma once

#include<llvm/IR/DataLayout.h>
#include <llvm/IR/Type.h>

namespace anvill {

std::string TranslateType(llvm::Type &type, llvm::DataLayout* dl);
std::string TranslateType(llvm::Type &type);

}  // namespace anvill