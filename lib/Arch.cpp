#include <vector>

#include "anvill/Arch.h"
#include "anvill/Decl.h"

#include <glog/logging.h>
#include <remill/Arch/Arch.h>

// namespace remill {
// class Arch;
// class IntrinsicTable;
// struct Register;
// }  // namespace remill

namespace anvill {

// Try to allocate a register for the argument based on the register constraints
// and what has already been reserved. Return nullptr if there is no possible
// register allocation.
remill::Register *TryRegisterAllocate(
    const llvm::Argument &argument, std::vector<bool> &reserved,
    const std::vector<RegisterConstraint> &register_constraints) {
  llvm::Type &type = *argument.getType();

  SizeConstraint size_constraint;
  TypeConstraint type_constraint;

  if (type.isIntegerTy()) {
    type_constraint = kTypeInt;
    auto derived = llvm::cast<llvm::IntegerType>(type);
    unsigned int width = derived.getBitWidth();
    if (width == 64) {
      size_constraint = kMinBit64;
    } else {
      // TODO: I know that this is wrong but for now its fine
      size_constraint = kMinBit32;
    }
  } else if (type.isFloatTy()) {
    type_constraint = kTypeFloat;
    // We automatically know it is 32-bit IEEE floating point type
    size_constraint = kMinBit32;
  } else if (type.isDoubleTy()) {
    type_constraint = kTypeFloat;
    // We automatically know it is 64-bit IEEE floating point type
    size_constraint = kMinBit64;
  } else if (type.isPointerTy()) {
    type_constraint = kTypeIntegral;
    size_constraint = kMinBit64;
  }
  // TODO: Handle other types

  for (size_t i = 0; i < register_constraints.size(); i++) {
    if (reserved[i]) {
      continue;
    }

    const RegisterConstraint &constraint = register_constraints[i];
    // Iterate through the different sizes of a single register to find the smallest possible match
    for (auto const &variant : constraint.variants) {
      if (size_constraint & variant.size_constraint && 
          type_constraint & variant.type_constraint) {
        reserved[i] = true;
        remill::Register *reg = 
            new remill::Register(variant.register_name, 0, 0, 0, &type);
        return reg;
      }
    }
  }
    return nullptr;
}

std::vector<anvill::ValueDecl> X86_64_SysV::BindReturnValues(
    const llvm::Function &function) {
  std::vector<anvill::ValueDecl> return_value_declarations;

  for (auto &block : function) {
    for (auto &inst : block) {
      if (auto return_inst = llvm::dyn_cast<llvm::ReturnInst>(&inst)) {
        anvill::ValueDecl value_declaration = {};

        const llvm::Value *value = return_inst->getReturnValue();
        if (!value) continue;
        value_declaration.type = value->getType();

        if (value_declaration.type->isIntOrPtrTy()) {
          // Allocate EAX for an integer or pointer
          value_declaration.reg =
              new remill::Register("RAX", 0, 8, 0, value->getType());
        } else if (value_declaration.type->isFloatingPointTy()) {
          // Allocate XMM0 for a floating point value
          value_declaration.reg =
              new remill::Register("XMM0", 0, 16, 0, value->getType());
        } else {
          LOG(ERROR) << "Encountered an unknown return type, could not bind "
                        "it... quitting";
          LOG(ERROR) << value->getType()->getTypeID();
          exit(1);
        }
        return_value_declarations.push_back(value_declaration);
      }
    }
  }

  return return_value_declarations;
}

std::vector<anvill::ParameterDecl> X86_64_SysV::BindParameters(
    const llvm::Function &function) {
  std::vector<anvill::ParameterDecl> parameter_declarations;

  // Create a map of names to parameters
  std::map<unsigned int, std::string> param_names;
  for (auto &block : function) {
    for (auto &inst : block) {
      if (auto debug_inst = llvm::dyn_cast<llvm::DbgInfoIntrinsic>(&inst)) {
        if (auto value_intrin = llvm::dyn_cast<llvm::DbgDeclareInst>(&inst)) {
          const llvm::MDNode *mdn = value_intrin->getVariable();
          const llvm::DILocalVariable *div =
              llvm::cast<llvm::DILocalVariable>(mdn);

          // Make sure it is actually an argument
          if (div->getArg() != 0) {
            LOG(INFO) << div->getArg() << " : " << div->getName().data();
            param_names[div->getArg()] = div->getName().data();
          }
        } else if (auto value_intrin =
                       llvm::dyn_cast<llvm::DbgValueInst>(debug_inst)) {
          const llvm::MDNode *mdn = value_intrin->getVariable();
          const llvm::DILocalVariable *div =
              llvm::cast<llvm::DILocalVariable>(mdn);

          if (div->getArg() != 0) {
            LOG(INFO) << div->getArg() << " : " << div->getName().data();
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

  // Used to keep track of which registers have been allocated
  std::vector<bool> allocated(register_constraints.size(), false);

  // Stack position of the first argument
  unsigned int stack_offset = 16;

  for (auto &argument : function.args()) {
    anvill::ParameterDecl declaration = {};
    declaration.type = argument.getType();

    // Try to allocate from a register
    if (remill::Register *reg =
            TryRegisterAllocate(argument, allocated, register_constraints)) {
      declaration.reg = reg;
    } else {
      // TODO: do I need to worry about register type?
      remill::Register *mem_reg =
          new remill::Register("RSP", stack_offset, 8, 0, argument.getType());
      stack_offset += 8;
      declaration.mem_reg = mem_reg;
    }

    // Try to get a name for the IR parameter
    // Need to add 1 because param_names uses logical numbering, but
    // argument.getArgNo() uses index numbering
    declaration.name = param_names[argument.getArgNo() + 1];

    parameter_declarations.push_back(declaration);
  }

  return parameter_declarations;
}

remill::Register *X86_64_SysV::BindReturnStackPointer(const llvm::Function &function) {
  // For the X86_64_SysV ABI, it is always:
  //
  // "return_stack_pointer": {
  //     "offset": "8",
  //     "register": "RSP",
  //     "type": "L"
  // }

  auto int64_ptr_ty = llvm::IntegerType::get(function.getContext(), 64);
  return new remill::Register("RSP", 8, 8, 0, int64_ptr_ty);
}

// TODO: This doesn't really fit here so I will need to find a better place for
// this. It also needs to be rewritten to conform to spec so its okay to leave
// it here for now.
std::string TranslateType(const llvm::Type &type) {
  unsigned int id = type.getTypeID();

  std::string ret;
  switch (id) {
    case llvm::Type::VoidTyID: {
      ret = "void";
      break;
    }
    case llvm::Type::HalfTyID: {
      ret = "float16";
      break;
    }
    case llvm::Type::FloatTyID: {
      ret = "float32";
      break;
    }
    case llvm::Type::DoubleTyID: {
      ret = "float64";
      break;
    }

    case llvm::Type::IntegerTyID: {
      ret = "int";
      auto derived = llvm::cast<llvm::IntegerType>(type);
      ret += std::to_string(derived.getBitWidth());
      break;
    }
    case llvm::Type::FunctionTyID: {
      ret = "func";
      break;
    }
    case llvm::Type::StructTyID: {
      LOG(INFO) << "struct";
      ret = "struct";
      auto struct_ptr = llvm::cast<llvm::StructType>(&type);
      std::string struct_list = "";
      LOG(INFO) << struct_ptr->getNumElements();
      for (unsigned i = 0; i < struct_ptr->getNumElements(); i++) {
        if (struct_ptr->getElementType(i)->isPtrOrPtrVectorTy()) {
          struct_list += "ptr_unknown";
          continue;
        }
        struct_list +=
            "(" + TranslateType(*struct_ptr->getElementType(i)) + ")";
      }
      ret += " [" + struct_list + "]";

      break;
    }
    case llvm::Type::ArrayTyID: {
      ret = "array";
      break;
    }
    case llvm::Type::PointerTyID: {
      ret = "ptr";
      auto derived = llvm::dyn_cast<llvm::PointerType>(&type);
      // Get the type of the pointee
      ret += " " + TranslateType(*derived->getElementType());
      break;
    }

    default:
      LOG(ERROR) << "Could not translate TypeID: " << id;
      break;
  }
  return ret;
}

}  // namespace anvill