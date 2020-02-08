#include <vector>

#include "Arch.h"
#include "anvill/Decl.h"

#include <glog/logging.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include <llvm/IR/Attributes.h>

namespace remill {
class Arch;
class IntrinsicTable;
struct Register;
}  // namespace remill

namespace anvill {

// Return true if the RegisterConstraint contains the named variant.
bool RegisterConstraint::ContainsVariant(const std::string& name) const {
  for (const auto &v : variants) {
    if (v.register_name == name) {
      return true;
    }
  }
  return false;
}

// Try to recover parameter names using debug information. Otherwise, name the
// parameters with the form "param_x". The mapping of the return value is
// positional starting at 1.
std::map<unsigned, std::string> TryRecoverParamNames(
    const llvm::Function &function) {
  std::map<unsigned int, std::string> param_names;

  // Iterate through all the instructions and look for debug intrinsics that
  // give us debug information about the parameters. We need to do this because
  // arg.uses() and arg.users() both do not take into account debug intrinsics.
  for (auto &block : function) {
    for (auto &inst : block) {
      if (auto debug_inst = llvm::dyn_cast<llvm::DbgInfoIntrinsic>(&inst)) {
        if (auto value_intrin = llvm::dyn_cast<llvm::DbgDeclareInst>(&inst)) {
          const llvm::MDNode *mdn = value_intrin->getVariable();
          const llvm::DILocalVariable *div =
              llvm::cast<llvm::DILocalVariable>(mdn);

          // Make sure it is actually an argument
          if (div->getArg() != 0) {
            param_names[div->getArg()] = div->getName().data();
          }
        } else if (auto value_intrin =
                       llvm::dyn_cast<llvm::DbgValueInst>(debug_inst)) {
          const llvm::MDNode *mdn = value_intrin->getVariable();
          const llvm::DILocalVariable *div =
              llvm::cast<llvm::DILocalVariable>(mdn);

          if (div->getArg() != 0) {
            param_names[div->getArg()] = div->getName().data();
          }
        }
      }
    }
  }

  // If we don't have names for some parameters then automatically name them
  unsigned int num_args =
      (unsigned int)(function.args().end() - function.args().begin());
  for (unsigned int i = 1; i <= num_args; i++) {
    if (!param_names.count(i)) {
      param_names[i] = "param" + std::to_string(i);
    }
  }

  return param_names;
}

}  // namespace anvill