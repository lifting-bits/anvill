#pragma once

#include <remill/Arch/Arch.h>
#include <llvm/IR/Type.h>

namespace llvm_utils {

std::size_t EstimateSize(const remill::Arch *arch, llvm::Type *type);

}
