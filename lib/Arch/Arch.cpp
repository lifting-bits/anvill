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

// Try to allocate a register for the argument based on the register constraints
// and what has already been reserved. Return nullptr if there is no possible
// register allocation.
const remill::Register *CallingConvention::TryRegisterAllocate(
    llvm::Type &type, std::vector<bool> &reserved,
    const std::vector<RegisterConstraint> &register_constraints) {
  SizeConstraint size_constraint;
  TypeConstraint type_constraint;

  switch (type.getTypeID()) {
    case llvm::Type::IntegerTyID: {
      type_constraint = kTypeInt;
      auto derived = llvm::cast<llvm::IntegerType>(type);
      unsigned int width = derived.getBitWidth();
      if (width <= 8) {
        size_constraint = kMinBit8;
      } else if (width <= 16) {
        size_constraint = kMinBit16;
      } else if (width <= 32) {
        size_constraint = kMinBit32;
      } else if (width <= 64) {
        size_constraint = kMinBit64;
      } else if (width <= 80) {
        size_constraint = kMinBit80;
      } else if (width <= 128) {
        size_constraint = kMinBit128;
      } else {
        LOG(FATAL) << "Integer too big: "
                   << remill::LLVMThingToString(&derived);
      }
      break;
    }
    case llvm::Type::FloatTyID: {
      type_constraint = kTypeFloat;
      // We automatically know it is 32-bit IEEE floating point type
      size_constraint = kMinBit32;
      break;
    }
    case llvm::Type::DoubleTyID: {
      type_constraint = kTypeFloat;
      // We automatically know it is 64-bit IEEE floating point type
      size_constraint = kMinBit64;
      break;
    }
    case llvm::Type::PointerTyID: {
      type_constraint = kTypeIntegral;
      size_constraint = kMinBit64;
      break;
    }
    case llvm::Type::X86_FP80TyID: {
      type_constraint = kTypeIntegral;
      size_constraint = kMinBit80;
      break;
    }
    case llvm::Type::VectorTyID: {
      type_constraint = kTypeFloatOrVec;
      size_constraint = kMinBit80;
      break;
    }
    default: {
      LOG(FATAL) << "Could not assign type and size constraints in "
                    "TryRegisterAllocate() for type "
                 << remill::LLVMThingToString(&type);
      // TODO(aty): Handle other types like X86_MMXTyID, etc.
      break;
    }
  }

  for (size_t i = 0; i < register_constraints.size(); i++) {
    if (reserved[i]) {
      continue;
    }

    const RegisterConstraint &constraint = register_constraints[i];
    // Iterate through the different sizes of a single register to find the
    // smallest possible match
    for (auto const &variant : constraint.variants) {
      if (size_constraint & variant.size_constraint &&
          type_constraint & variant.type_constraint) {
        auto reg = arch->RegisterByName(variant.register_name);
        if (!reg) {
          LOG(FATAL) << "Could not find the register";
        }
        reserved[i] = true;
        return reg;
      }
    }
  }
  return nullptr;
}

std::unique_ptr<std::vector<anvill::ValueDecl>>
CallingConvention::TryReturnThroughRegisters(
    const llvm::StructType &st,
    const std::vector<RegisterConstraint> &constraints) {
  std::vector<bool> reserved(constraints.size(), false);
  return TryReturnThroughRegistersInternal(st, reserved, constraints);
}

std::unique_ptr<std::vector<anvill::ValueDecl>>
CallingConvention::TryReturnThroughRegistersInternal(
    const llvm::StructType &st, std::vector<bool> &reserved,
    const std::vector<RegisterConstraint> &constraints) {
  auto ret = std::make_unique<std::vector<anvill::ValueDecl>>();
  for (unsigned i = 0; i < st.getNumElements(); i++) {
    const llvm::Type *elem_type = st.getElementType(i);
    if (llvm::isa<llvm::CompositeType>(elem_type)) {
      if (llvm::isa<llvm::StructType>(elem_type)) {
        // Recurse and try to allocate the elements of the inner struct. If the
        // inner struct returns a nullptr, then return a nullptr because we
        // couldn't fully allocate the inner structure. Otherwise, combine the
        // declarations that were made in the recursive call to our
        // declarations.
        auto inner_ret =
            TryReturnThroughRegistersInternal(st, reserved, constraints);
        if (!inner_ret) {
          return nullptr;
        } else {
          ret->insert(ret->end(), std::make_move_iterator(inner_ret->begin()),
                      std::make_move_iterator(inner_ret->end()));
        }
      } else {
        // TODO(aty): Might have to come back to this but structs don't seem to
        // be split over any other composite types such as arrays or vectors.
        return nullptr;
      }
    } else {
      // Value is a non-composite type so proceed normally.
      anvill::ValueDecl value_decl = {};
      auto reg =
          TryRegisterAllocate(*st.getElementType(i), reserved, constraints);
      if (reg) {
        value_decl.reg = reg;
        value_decl.type = st.getElementType(i);
      } else {
        // The struct cannot be split over registers.
        return nullptr;
      }
      ret->push_back(value_decl);
    }
  }

  return ret;
}

}  // namespace anvill