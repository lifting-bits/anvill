#include <anvill/SliceInterpreter.h>
#include <anvill/SliceManager.h>

namespace anvill {
llvm::GenericValue
SliceInterpreter::executeSlice(SliceID sliceId,
                               llvm::ArrayRef<llvm::GenericValue> ArgValue) {
  auto f = this->execEngine->FindFunctionNamed(
      SliceManager::getFunctionName(sliceId));

  assert(f != nullptr);
  return this->execEngine->runFunction(f, ArgValue);
}
}  // namespace anvill