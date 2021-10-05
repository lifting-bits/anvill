#include <anvill/SliceInterpreter.h>
#include <anvill/SliceManager.h>

namespace anvill {
llvm::GenericValue
SliceInterpreter::executeSlice(SliceID sliceId,
                               llvm::ArrayRef<llvm::GenericValue> ArgValue) {
  auto F = this->execEngine->FindFunctionNamed(
      SliceManager::getFunctionName(sliceId));

  assert(F != nullptr);
  return this->execEngine->runFunction(F, ArgValue);
}
}  // namespace anvill