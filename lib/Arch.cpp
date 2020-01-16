#include <vector>

#include "anvill/Arch.h"
#include "anvill/Decl.h"

#include <glog/logging.h>
#include <remill/Arch/Arch.h>

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
      if (width == 64) {
        size_constraint = kMinBit64;
      } else {
        // TODO(aty): I know that this is wrong but for now its fine
        size_constraint = kMinBit32;
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
    }
    default: {
      LOG(FATAL) << "Could not assign type and size constraints in "
                    "TryRegisterAllocate()";
      // TODO(aty): Handle other types like X86_MMXTyID, etc.
      break;
    }
  }

  for (size_t i = 0; i < register_constraints.size(); i++) {
    if (reserved[i]) continue;

    const RegisterConstraint &constraint = register_constraints[i];
    // Iterate through the different sizes of a single register to find the
    // smallest possible match
    for (auto const &variant : constraint.variants) {
      if (size_constraint & variant.size_constraint &&
          type_constraint & variant.type_constraint) {
        reserved[i] = true;
        return arch->RegisterByName(variant.register_name);
      }
    }
  }
  return nullptr;
}

// For each element of the struct, try to allocate it to a register, if all of
// them can be allocated, then return that allocation. Otherwise return a
// nullptr.
std::unique_ptr<std::vector<anvill::ValueDecl>> CallingConvention::TryReturnThroughRegisters(
    const llvm::StructType &st,
    const std::vector<RegisterConstraint> &constraints) {
  auto ret = std::make_unique<std::vector<anvill::ValueDecl>>();
  std::vector<bool> reserved(constraints.size(), false);
  for (unsigned i = 0; i < st.getNumElements(); i++) {
    anvill::ValueDecl value_decl = {};
    auto reg =
        TryRegisterAllocate(*st.getElementType(i), reserved, constraints);
    if (reg) {
      value_decl.reg = reg;
      value_decl.type = st.getElementType(i);
    } else {
      // The struct cannot be split over registers
      return nullptr;
    }
    ret->push_back(value_decl);
  }

  return ret;
}

std::vector<anvill::ValueDecl> X86_64_SysV::BindReturnValues(
    const llvm::Function &function) {
  std::vector<anvill::ValueDecl> return_value_declarations;
  anvill::ValueDecl value_declaration = {};
  llvm::Type *ret_type = function.getReturnType();
  value_declaration.type = ret_type;

  switch (ret_type->getTypeID()) {
    case llvm::Type::IntegerTyID:
    case llvm::Type::PointerTyID: {
      // Allocate RAX for an integer or pointer
      value_declaration.reg = arch->RegisterByName("RAX");
      break;
    }
    case llvm::Type::FloatTyID: {
      // Allocate XMM0 for a floating point value
      value_declaration.reg = arch->RegisterByName("XMM0");
      break;
    }
    case llvm::Type::StructTyID: {
      // Try to split the struct over the registers
      std::vector<bool> allocated(return_register_constraints.size(), false);
      auto struct_ptr = llvm::cast<llvm::StructType>(value_declaration.type);
      auto mapping =
          TryReturnThroughRegisters(*struct_ptr, return_register_constraints);
      if (mapping) {
        // There is a valid split over registers, so add the mapping
        return *mapping;
      } else {
        // Struct splitting didn't work so do RVO. Assume that the pointer
        // to the return value resides in RAX.
        value_declaration.reg = arch->RegisterByName("RAX");
      }
      break;
    }
    default: {
      LOG(ERROR) << "Encountered an unknown return type";
      exit(1);
    }
  }

  return_value_declarations.push_back(value_declaration);

  return return_value_declarations;
}

std::vector<anvill::ParameterDecl> X86_64_SysV::BindParameters(
    const llvm::Function &function) {
  std::vector<anvill::ParameterDecl> parameter_declarations;
  auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // Used to keep track of which registers have been allocated
  std::vector<bool> allocated(parameter_register_constraints.size(), false);

  // Stack position of the first argument
  unsigned int stack_offset = 16;

  for (auto &argument : function.args()) {
    anvill::ParameterDecl declaration = {};
    declaration.type = argument.getType();

    // Try to allocate from a register. If a register is not available then
    // allocate from the stack.
    if (const remill::Register *reg = TryRegisterAllocate(
            *argument.getType(), allocated, parameter_register_constraints)) {
      declaration.reg = reg;
    } else {
      declaration.mem_offset = stack_offset;
      declaration.mem_reg = arch->RegisterByName("RSP");
      stack_offset += dl.getTypeAllocSize(argument.getType());
    }

    // Try to get a name for the IR parameter
    // Need to add 1 because param_names uses logical numbering, but
    // argument.getArgNo() uses index numbering
    declaration.name = param_names[argument.getArgNo() + 1];

    parameter_declarations.push_back(declaration);
  }

  return parameter_declarations;
}

void X86_64_SysV::BindReturnStackPointer(
      FunctionDecl &fdecl, const llvm::Function &func) {
  // For the X86_64_SysV ABI, it is always:
  //
  // "return_stack_pointer": {
  //     "offset": "8",
  //     "register": "RSP",
  //     "type": "L"
  // }

  fdecl.return_stack_pointer_offset = 8;
  fdecl.return_stack_pointer = arch->RegisterByName("RSP");
}

void X86_64_SysV::AllocateSignature(FunctionDecl &fdecl, const llvm::Function &func) {
  return;
}

// Allocates the elements of the function signature of func to memory or
// registers. This includes parameters/arguments, return values, and the return
// stack pointer.
void X86_C::AllocateSignature(FunctionDecl &fdecl, const llvm::Function &func) {
  // Bind return values first to see if we have injected an sret into the
  // parameter list. Then, bind the parameters. It is important that we bind the
  // return values before the parameters in case we inject an sret.
  bool injected_sret = false;
  fdecl.returns = BindReturnValues(func, injected_sret);
  fdecl.params = BindParameters(func, injected_sret);
  BindReturnStackPointer(fdecl, func);
}

std::vector<ParameterDecl> X86_C::BindParameters(
    const llvm::Function &function, bool injected_sret) {
  std::vector<anvill::ParameterDecl> parameter_declarations;
  auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // Stack position of the first argument
  unsigned int stack_offset = 4;

  // If there is an injected sret (an implicit sret) then we need to allocate
  // the first parameter to the sret struct. The type of said sret parameter
  // will be the return type of the function.
  if (injected_sret) {
    anvill::ParameterDecl decl = {};
    decl.type = function.getReturnType();
    decl.mem_offset = stack_offset;
    decl.mem_reg = arch->RegisterByName("ESP");
    stack_offset += dl.getTypeAllocSize(decl.type);
    parameter_declarations.push_back(decl);
  }

  for (auto &argument : function.args()) {
    anvill::ParameterDecl declaration = {};
    declaration.type = argument.getType();

    // Since there are no registers, just allocate from the stack
    declaration.mem_offset = stack_offset;
    declaration.mem_reg = arch->RegisterByName("ESP");
    stack_offset += dl.getTypeAllocSize(argument.getType());

    // Get a name for the IR parameter.
    // Need to add 1 because param_names uses logical numbering, but
    // argument.getArgNo() uses index numbering.
    declaration.name = param_names[argument.getArgNo() + 1];
    parameter_declarations.push_back(declaration);
  }

  return parameter_declarations;
}

std::vector<anvill::ValueDecl> X86_C::BindReturnValues(
    const llvm::Function &function, bool &injected_sret) {
  std::vector<anvill::ValueDecl> return_value_declarations;
  anvill::ValueDecl value_declaration = {};
  injected_sret = false;

  // If there is an sret parameter then it is a special case. For the X86_C ABI,
  // the sret parameters are guarenteed the be in %eax. In this case, we can
  // assume the actual return value of the function will be the sret struct
  // pointer.
  for (auto arg = function.arg_begin(); arg != function.arg_end(); arg++) {
    if (arg->hasStructRetAttr()) {
      value_declaration.type = arg->getType();
      value_declaration.reg = arch->RegisterByName("EAX");
      return_value_declarations.push_back(value_declaration);
      return return_value_declarations;
    }
  }

  llvm::Type *ret_type = function.getReturnType();
  value_declaration.type = ret_type;

  switch (ret_type->getTypeID()) {
    case llvm::Type::IntegerTyID:
    case llvm::Type::PointerTyID: {
      // Allocate EAX for an integer or pointer
      value_declaration.reg = arch->RegisterByName("EAX");
      break;
    }
    case llvm::Type::FloatTyID: {
      // Allocate ST0 for a floating point value
      value_declaration.reg = arch->RegisterByName("ST0");
      break;
    }
    case llvm::Type::StructTyID: {
      // Try to split the struct over the registers
      std::vector<bool> allocated(return_register_constraints.size(), false);
      auto struct_ptr = llvm::cast<llvm::StructType>(value_declaration.type);
      auto mapping =
          TryReturnThroughRegisters(*struct_ptr, return_register_constraints);
      if (mapping) {
        // There is a valid split over registers, so return the mapping
        return *mapping;
      } else {
        // Struct splitting didn't work so do RVO. Assume that the pointer
        // to the return value resides in EAX. In this case we have injected an
        // sret into the first parameter so we need to take note of that.
        injected_sret = true;
        value_declaration.reg = arch->RegisterByName("EAX");
      }
      break;
    }
    default: {
      LOG(ERROR) << "Encountered an unknown return type";
      exit(1);
    }
  }
  return_value_declarations.push_back(value_declaration);

  return return_value_declarations;
}

// The return stack pointer describes where the stack will be upon return from
// the function in terms of the registers of the current function. For x86_C,
// this is usually ESP + 4 since that is where the return address is stored.
void X86_C::BindReturnStackPointer(
      FunctionDecl &fdecl, const llvm::Function &func) {
  // Check if the first argument is an sret. If it is, then by the X86_C ABI,
  // the callee is responbile for returning said sret argument in %eax and
  // cleaning up the sret argument with a `ret 4`. This changes the
  // return_stack_pointer offset because it will now be 4 bytes higher than we
  // thought.
  //
  // However, even if there is sret on the second argument as well, we do not
  // need to worry about this. For some reason the callee is only responsible
  // for cleaning up the case where an sret argument is passed in as the first
  // argument.
  if (func.hasParamAttribute(0, llvm::Attribute::StructRet)) {
    fdecl.return_stack_pointer_offset = 8;
  } else {
    fdecl.return_stack_pointer_offset = 4;
  }

  fdecl.return_stack_pointer = arch->RegisterByName("ESP");
}

}  // namespace anvill