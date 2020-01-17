#include <vector>

#include "anvill/Arch.h"
#include "anvill/Decl.h"

#include <glog/logging.h>
#include <remill/Arch/Arch.h>

namespace anvill {

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

std::vector<ParameterDecl> X86_C::BindParameters(
    const llvm::Function &function, bool injected_sret) {
  std::vector<anvill::ParameterDecl> parameter_declarations;
  auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // stack_offset describes the position of the first stack argument on entry to
  // the callee. For X86_C, this is at [esp + 4] because the return address is
  // pushed onto the stack upon call instruction at [esp].
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

}  // namespace anvill