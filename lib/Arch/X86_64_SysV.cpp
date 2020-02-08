#include <vector>

#include "Arch.h"
#include "../AllocationState.h"
#include "anvill/Decl.h"

#include <glog/logging.h>
#include <remill/Arch/Arch.h>

namespace anvill {

// Allocates the elements of the function signature of func to memory or
// registers. This includes parameters/arguments, return values, and the return
// stack pointer.
void X86_64_SysV::AllocateSignature(FunctionDecl &fdecl,
                                    const llvm::Function &func) {
  // Bind return values first to see if we have injected an sret into the
  // parameter list. Then, bind the parameters. It is important that we bind the
  // return values before the parameters in case we inject an sret.
  bool injected_sret = false;
  fdecl.returns = BindReturnValues(func, injected_sret);
  fdecl.params = BindParameters(func, injected_sret);
  BindReturnStackPointer(fdecl, func);
}

void X86_64_SysV::BindReturnStackPointer(FunctionDecl &fdecl,
                                         const llvm::Function &func) {
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

std::vector<anvill::ValueDecl> X86_64_SysV::BindReturnValues(
    const llvm::Function &function, bool &injected_sret) {
  std::vector<anvill::ValueDecl> ret;
  anvill::ValueDecl value_declaration = {};
  injected_sret = false;

  // If there is an sret parameter then it is a special case. For the
  // X86_64_SysV ABI, the sret parameters are guarenteed the be in %rax. In this
  // case, we can assume the actual return value of the function will be the
  // sret struct pointer.
  if (function.hasStructRetAttr()) {
    // Check both first and second parameter because llvm does that in
    // llvm::Function::hasStructRetAttr()
    if (function.hasParamAttribute(0, llvm::Attribute::StructRet)) {
      value_declaration.type = function.getParamByValType(0);
    } else if (function.hasParamAttribute(1, llvm::Attribute::StructRet)) {
      value_declaration.type = function.getParamByValType(1);
    } else {
      LOG(FATAL) << "Function has sret that is not the first or second argument";
    }
    value_declaration.reg = arch->RegisterByName("RAX");
    ret.push_back(value_declaration);
    return ret;
  }

  llvm::Type *ret_type = function.getReturnType();
  value_declaration.type = ret_type;

  switch (ret_type->getTypeID()) {
    case llvm::Type::IntegerTyID:
    case llvm::Type::PointerTyID: {
      // Allocate RAX for an integer or pointer
      value_declaration.reg = arch->RegisterByName("RAX");
      break;
    }
    case llvm::Type::FloatTyID:
    case llvm::Type::DoubleTyID: {
      // Allocate XMM0 for a floating point value
      value_declaration.reg = arch->RegisterByName("XMM0");
      break;
    }
    case llvm::Type::VectorTyID:
    case llvm::Type::ArrayTyID:
    case llvm::Type::StructTyID: {
      // Try to split the composite type over registers
      auto comp_ptr = llvm::cast<llvm::CompositeType>(value_declaration.type);
      AllocationState alloc_ret(return_register_constraints, arch);
      auto mapping =
          alloc_ret.TryRegisterAllocate(*comp_ptr);
      if (mapping) {
        // There is a valid split over registers, so add the mapping
        return alloc_ret.CoalescePacking(mapping.getValue());
      } else {
        // Composite type splitting didn't work so do RVO. Assume that the pointer
        // to the return value resides in RAX.
        injected_sret = true;
        value_declaration.reg = arch->RegisterByName("RAX");
      }
      break;
    }
    case llvm::Type::X86_MMXTyID: {
      value_declaration.reg = arch->RegisterByName("MM0");
      break;
    }
    case llvm::Type::X86_FP80TyID: {
      value_declaration.reg = arch->RegisterByName("ST0");
    }
    default: {
      LOG(ERROR) << "Encountered an unknown return type";
      exit(1);
    }
  }

  ret.push_back(value_declaration);

  return ret;
}

// For X86_64_SysV, the general argument passing behavior is, try to pass the
// arguments in registers RDI, RSI, RDX, RCX, R8, R9 from integral types and
// XMM0 - XMM7 for float types. If the argument is a struct but can be
// completely split over the above registers, then greedily split it over the
// registers. Otherwise, the struct is passed entirely on the stack. If we run
// our of registers then pass the rest of the arguments on the stack.
std::vector<anvill::ParameterDecl> X86_64_SysV::BindParameters(
    const llvm::Function &function, bool injected_sret) {
  std::vector<anvill::ParameterDecl> parameter_declarations;
  auto param_names = TryRecoverParamNames(function);
  llvm::DataLayout dl(function.getParent());

  // Used to keep track of which registers have been allocated
  AllocationState alloc_param(parameter_register_constraints, arch);

  // Stack offset describes the stack position of the first stack argument on
  // entry to the callee. For X86_64_SysV, this is [rsp + 8] since there is the
  // return address at [rsp].
  unsigned int stack_offset = 8;

  // If there is an injected sret (an implicit sret) then we need to allocate
  // the first parameter to the sret struct. The type of said sret parameter
  // will be the return type of the function.
  if (injected_sret) {
    anvill::ParameterDecl decl = {};
    decl.name = "param0";
    decl.type = function.getReturnType();
    decl.reg = arch->RegisterByName("RAX");
    alloc_param.reserved[0] = true;
    parameter_declarations.push_back(decl);
  }

  for (auto &argument : function.args()) {
    anvill::ParameterDecl declaration = {};
    declaration.type = argument.getType();

    // Try to allocate from a register. If a register is not available then
    // allocate from the stack.
    if (auto allocation = alloc_param.TryRegisterAllocate(*declaration.type)) {
      declaration.reg = allocation->front().reg;
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

}  // namespace anvill