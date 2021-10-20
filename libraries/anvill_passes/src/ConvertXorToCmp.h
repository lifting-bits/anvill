#include <llvm/Pass.h>

namespace anvill {

class ConvertXorToCmp final : public llvm::FunctionPass {
 public:
  ConvertXorToCmp(void) : llvm::FunctionPass(ID) {}

  bool runOnFunction(llvm::Function &func) override;

 private:
  static char ID;
};
}  // namespace anvill
