#include <anvill/Declarations.h>
#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>

#include <memory>

#include "Arch.h"

namespace anvill {

class Stub : public CallingConvention {
 public:
  Stub() : CallingConvention(0, nullptr) {}

  llvm::Error AllocateSignature(FunctionDecl &fdecl,
                                llvm::Function &func) override {
    return llvm::createStringError(
        std::errc::invalid_argument,
        "No longer supporting allocating signatures");
  }
};

std::unique_ptr<CallingConvention> CallingConvention::CreateStubABI() {

  return std::make_unique<Stub>();
}
}  // namespace anvill