#pragma once

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/Type.h>

namespace anvill {

std::string TranslateType(llvm::Type &type, const llvm::DataLayout &dl);

}  // namespace anvill