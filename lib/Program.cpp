//
// Created by Peter Goodman on 2019-10-11.
//

#include "anvill/Program.h"

#include <algorithm>
#include <map>
#include <sstream>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <llvm/IR/Type.h>
#include <llvm/IR/DerivedTypes.h>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>

#include "anvill/Decl.h"

#include <glog/logging.h>

namespace anvill {

// A byte, its address, and any associated metadata. The metadata is
// updated throughout the lifting/decompiling process.
struct Byte::Impl {
  uint8_t value;

  bool _unused:1;

  // Is the value of this byte undefined? Our model of the stack
  // begins with all stack bytes, unless explicitly specified, as
  // undefined.
  bool is_undefined:1;

  // Is this byte from the stack?
  bool is_stack:1;

  // Is this byte the beginning of a variable?
  bool is_variable_head:1;

  // These require `is_executable` to be `true`.
  bool is_function_head:1;

  // Your basic permissions.
  bool is_readable:1;

  // If `false`, then the implied semantic is that the byte will *never* be
  // writable. For example, if we're decompiling a snapshot or a core dump,
  // then the data associated with the ELF GOT/PLT sections would likely we
  // treated as being "constant" so that we could read through them.
  //
  // NOTE(pag): For jump tables to work most effectively, we expect the bytes
  //            that store the offsets/displacements/etc. to be marked as
  //            constants.
  bool is_writeable:1;

  // NOTE(pag): We *only* treat a byte as possibly belonging to an instruction
  //            if `is_writable` is false. The semantic here is that we're
  //            unprepared to handle self-modifying code. Further, we don't
  //            want to treat bytes that might be in executable stacks as being
  //            code.
  bool is_executable:1;

} __attribute__((packed));

static_assert(
    sizeof(Byte::Impl) == sizeof(uint16_t),
    "Invalid packing of `struct Byte::Impl`.");

enum ProgramEvent {
  kFunctionDeclared,
  kFunctionDefined,
  kGlobalVariableDeclared,
  kGlobalVariableDefined
};

// Default implementation of a program.
class Program::Impl {
 public:
  llvm::Error DeclareFunction(const FunctionDecl &decl_template);
  FunctionDecl *FindFunction(uint64_t address);
  void ForEachFunction(std::function<bool(const FunctionDecl *)> callback);
  void ForEachFunctionWithName(
      const std::string &name,
      std::function<bool(const FunctionDecl *)> callback);

  llvm::Error DeclareVariable(const GlobalVarDecl &decl_template);
  GlobalVarDecl *FindVariable(uint64_t address);
  GlobalVarDecl *FindVariable(const std::string &name);
  void ForEachVariable(std::function<bool(const GlobalVarDecl *)> callback);
  void ForEachVariableWithName(
      const std::string &name,
      std::function<bool(const GlobalVarDecl *)> callback);

  Byte::Impl *FindByte(uint64_t address);
  llvm::Error MapRange(const ByteRange &range);
  llvm::Error MapStack(uint64_t base_address, uint64_t limit_address,
                       uint64_t start_address);

  void EmitEvent(ProgramEvent event, uint64_t address) {}

  // Declarations for the functions.
  std::vector<std::unique_ptr<FunctionDecl>> funcs;
  std::unordered_map<uint64_t, FunctionDecl *> ea_to_func;
  std::unordered_multimap<std::string, FunctionDecl *> name_to_func;

  // Declarations for the variables.
  std::vector<std::unique_ptr<GlobalVarDecl>> vars;
  std::unordered_map<uint64_t, GlobalVarDecl *> ea_to_var;
  std::unordered_multimap<std::string, GlobalVarDecl *> name_to_var;

  // Values of all bytes mapped in memory, including additional
  // bits of metadata, and the address at which each byte is
  // loaded.
  //
  // The keys of the maps are the address of the last byte in
  // the range as represented in the mapped vector. The vectors
  // are sorted in order.
  std::map<uint64_t, std::vector<Byte::Impl>> bytes;

  // Initial stack pointer.
  uint64_t initial_stack_pointer{0};
  bool has_initial_stack_pointer{false};
};

namespace {

template <typename T>
static llvm::Error CheckValueDecl(
    const T &decl, llvm::LLVMContext &context,
    const char *desc, uint64_t func_address) {
  if (!decl.type) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Missing LLVM type information for %s "
        "in function declaration at '%lx'",
        desc, func_address);

  } else if (decl.type->isFunctionTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at '%lx' is a function type; "
        "did you mean to use a function pointer type?",
        desc, func_address);

  } else if (decl.type->isVoidTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at '%lx' is a void type; "
        "did you mean to use a void pointer type, or to "
        "exclude it entirely?",
        desc, func_address);

  } else if (&(decl.type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at '%lx' is associated "
        "with a different LLVM context than the function's "
        "architecture",
        desc, func_address);

  } else if (decl.reg && decl.mem_reg) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "A %s cannot be resident in both a "
        "register (%s) and a memory location (%s + %ld) in "
        "function declaration at '%lx'",
        desc, decl.reg->name.c_str(), decl.mem_reg->name.c_str(),
        decl.mem_offset, func_address);

  } else if (decl.reg &&
             &(decl.reg->type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at '%lx' is associated "
        "with a different LLVM context than the %s's "
        "register location",
        desc, func_address, desc);

  } else if (decl.mem_reg &&
             &(decl.mem_reg->type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at '%lx' is associated "
        "with a different LLVM context than the %s's "
        "memory location base register",
        desc, func_address, desc);

  } else if (decl.mem_reg && !decl.mem_reg->type->isIntegerTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Type of memory base register of %s in function "
        "declaration at '%lx' must be integral",
        desc, func_address);
  }

  return llvm::Error::success();
}

}  // namespace

bool Byte::IsReadableImpl(void) const {
  return impl->is_readable;
}

bool Byte::IsWriteableImpl(void) const {
  return impl->is_writeable;
}

bool Byte::IsExecutableImpl(void) const {
  return impl->is_executable;
}

bool Byte::IsStackImpl(void) const {
  return impl->is_stack;
}

bool Byte::IsUndefinedImpl(void) const {
  return impl->is_undefined;
}

bool Byte::SetUndefinedImpl(bool is_undef) const {
  if (impl->is_function_head && !impl->is_variable_head) {
    impl->is_undefined = is_undef;
    return true;
  } else {
    return false;
  }
}

uint8_t Byte::ValueImpl(void) const {
  return impl->value;
}

// Declare a function in this view.
llvm::Error Program::Impl::DeclareFunction(const FunctionDecl &tpl) {

  const auto byte = FindByte(tpl.address);
  if (byte) {
    if (!byte->is_executable) {
      return llvm::createStringError(
          std::make_error_code(std::errc::bad_address),
          "Function at address '%lx' is not executable.",
          tpl.address);

    } else if (byte->is_stack) {
      return llvm::createStringError(
          std::make_error_code(std::errc::bad_address),
          "Cannot declare function at address '%lx' "
          "within the stack.",
          tpl.address);
    }
  }

  if (auto existing_decl = FindFunction(tpl.address)) {
    return llvm::createStringError(
        std::make_error_code(std::errc::address_in_use),
        "The function '%s' is already declared at '%lx'",
        existing_decl->name.c_str(), existing_decl->address);
  }

  if (!tpl.arch) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Missing architecture for function declared at '%lx'",
        tpl.address);
  }

  auto &context = *(tpl.arch->context);

  if (tpl.type) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for function declaration at '%lx' "
        "should not be manually specified",
        tpl.address);
  }

  ValueDecl return_address = tpl.return_address;
  const auto pc_reg_name = tpl.arch->ProgramCounterRegisterName();
  if (auto pc_reg = tpl.arch->RegisterByName(pc_reg_name)) {
    if (!return_address.type) {
      return_address.type = pc_reg->type;
    } else if (!return_address.type->isIntegerTy()) {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Type of the return address in function declaration at "
          "'%lx' must be integral",
          tpl.address);
    } else if (return_address.type != pc_reg->type) {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Type of the return address in function declaration at "
          "'%lx' must match type of the '%s' register",
          tpl.address, pc_reg_name);
    }
  } else {
    return llvm::createStringError(
        std::make_error_code(std::errc::operation_canceled),
        "Cannot find register information for program counter "
        "register '%s'; has the semantics module for the architecture "
        "associated with the function declaration at '%lx' been loaded?",
        pc_reg_name, tpl.address);
  }

  auto err = CheckValueDecl(
      return_address, context, "return address", tpl.address);
  if (err) {
    return err;
  }

  for (auto &param : tpl.returns) {
    err = CheckValueDecl(
        param, context, "parameter", tpl.address);
    if (err) {
      return err;
    }
  }

  for (auto &ret : tpl.returns) {
    err = CheckValueDecl(
        ret, context, "return value", tpl.address);
    if (err) {
      return err;
    }
  }

  if (!tpl.return_stack_pointer) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "The return stack pointer base register must be provided",
        tpl.address);

  } else if (&(tpl.return_stack_pointer->type->getContext()) !=
             tpl.arch->context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for return base stack pointer "
        "regisetr '%s' in function declaration at '%lx' is associated "
        "with a different LLVM context than the function's "
        "architecture",
        tpl.return_stack_pointer->name.c_str(), tpl.address);

  } else if (!tpl.return_stack_pointer->type->isIntegerTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Type of base register '%s' used in exit stack pointer "
        "expression in function declaration at '%lx' must be integral",
        tpl.return_stack_pointer->name.c_str(), tpl.address);

  } else {
    auto sp_reg_name = tpl.arch->StackPointerRegisterName();
    auto real_sp_reg = tpl.arch->RegisterByName(sp_reg_name);
    if (!real_sp_reg) {
      return llvm::createStringError(
          std::make_error_code(std::errc::executable_format_error),
          "Could not locate stack pointer register '%s' in architecture "
          "'%s' for function declaration at '%lx'",
          sp_reg_name, remill::GetArchName(tpl.arch->arch_name).c_str(),
          tpl.address);
    }

    if (real_sp_reg->type != tpl.return_stack_pointer->type) {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Type of stack pointer register '%s' does not match the type "
          "of the exit stack pointer base register '%s' in function "
          "declaration at '%lx'",
          real_sp_reg->name.c_str(), tpl.return_stack_pointer->name.c_str(),
          tpl.address);
    }
  }

  // Figure out the return type of this function based off the return
  // values.
  llvm::Type *ret_type = nullptr;
  if (tpl.returns.empty()) {
    ret_type = llvm::Type::getVoidTy(context);

  } else if (tpl.returns.size() == 1) {
    ret_type = tpl.returns[0].type;

  // The multiple return value case is most interesting, and somewhere
  // where we see some divergence between C and what we will decompile.
  // For example, on 32-bit x86, a 64-bit return value might be spread
  // across EAX:EDX. Instead of representing this by a single value, we
  // represent it as a structure if two 32-bit ints, and make sure to say
  // that one part is in EAX, and the other is in EDX.
  } else {
    std::vector<llvm::Type *> ret_types;
    for (auto &ret_val : tpl.returns) {
      ret_types.push_back(ret_val.type);
    }
    ret_type = llvm::StructType::get(context, ret_types, true);
  }

  std::vector<llvm::Type *> param_types;
  for (auto &param_val : tpl.params) {
    param_types.push_back(param_val.type);
  }

  std::unique_ptr<FunctionDecl> decl(new FunctionDecl(std::move(tpl)));
  const auto decl_ptr = decl.get();
  decl_ptr->return_address = return_address;
  decl_ptr->is_valid = true;
  decl->type = llvm::FunctionType::get(ret_type, param_types, tpl.is_variadic);

  // Use the standard convention for adding names to anonymous
  // functions.
  if (decl->name.empty()) {
    std::stringstream ss;
    ss << "sub_" << std::hex << decl->address;
    ss.str().swap(decl->name);
  }

  funcs.emplace_back(std::move(decl));
  ea_to_func.emplace(decl_ptr->address, decl_ptr);
  name_to_func.emplace(decl_ptr->name, decl_ptr);

  if (byte) {
    byte->is_function_head = true;
    EmitEvent(kFunctionDefined, decl_ptr->address);
  } else {
    EmitEvent(kFunctionDeclared, decl_ptr->address);
  }

  return llvm::Error::success();
}

// Search for a specific function.
FunctionDecl *Program::Impl::FindFunction(uint64_t address) {
  const auto it = ea_to_func.find(address);
  if (it != ea_to_func.end()) {
    return it->second;
  } else {
    return nullptr;
  }
}

// Internal iterator over functions.
void Program::Impl::ForEachFunction(
    std::function<bool(const FunctionDecl *)> callback) {
  for (size_t i = 0; i < funcs.size(); ++i) {
    if (const auto decl = funcs[i].get()) {
      if (!callback(decl)) {
        return;
      }
    }
  }
}

// Internal iterator over each function declared with the same
// name.
void Program::Impl::ForEachFunctionWithName(
    const std::string &name,
    std::function<bool(const FunctionDecl *)> callback) {
  for (auto iterator_invalid = true; iterator_invalid; ) {
    iterator_invalid = false;
    const auto initial_num_funcs = funcs.size();
    for (auto range = name_to_func.equal_range(name);
         range.first != range.second;
         ++range.first) {
      if (!callback(range.first->second)) {
        return;
      } else if (initial_num_funcs != funcs.size()) {
        iterator_invalid = true;
        break;
      }
    }
  }
}

// Declare a variable in this view.
llvm::Error Program::Impl::DeclareVariable(const GlobalVarDecl &tpl) {
  if (auto existing_decl = FindVariable(tpl.address)) {
    return llvm::createStringError(
        std::make_error_code(std::errc::address_in_use),
        "The variable '%s' is already declared at '%lx'",
        existing_decl->name.c_str(), existing_decl->address);
  }

  if (!tpl.type) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Missing LLVM type information for variable declaration at '%lx'",
        tpl.address);

  } else if (tpl.type->isFunctionTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for variable declaration at '%lx' must "
        "not be an instance of 'llvm::FunctionType'",
        tpl.address);
  }

  auto byte = FindByte(tpl.address);
  if (byte && byte->is_stack) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Cannot declare global variable at '%lx' within the stack",
        tpl.address);
  }

  std::unique_ptr<GlobalVarDecl> decl(new GlobalVarDecl(tpl));

  // Use the standard convention for adding names to anonymous
  // variables.
  if (decl->name.empty()) {
    std::stringstream ss;
    ss << "data_" << std::hex << decl->address;
    ss.str().swap(decl->name);
  }

  const auto decl_ptr = decl.get();
  decl_ptr->is_valid = true;
  vars.emplace_back(std::move(decl));
  ea_to_var.emplace(decl_ptr->address, decl_ptr);
  name_to_var.emplace(decl_ptr->name, decl_ptr);

  if (byte) {
    byte->is_variable_head = true;
    EmitEvent(kGlobalVariableDefined, decl_ptr->address);
  } else {
    EmitEvent(kGlobalVariableDeclared, decl_ptr->address);
  }

  return llvm::Error::success();
}

// Search for a specific variable.
GlobalVarDecl *Program::Impl::FindVariable(uint64_t address) {
  const auto it = ea_to_var.find(address);
  if (it != ea_to_var.end()) {
    return it->second;
  } else {
    return nullptr;
  }
}

// Internal iterator over variables.
void Program::Impl::ForEachVariable(
    std::function<bool(const GlobalVarDecl *)> callback) {
  for (size_t i = 0; i < vars.size(); ++i) {
    if (const auto decl = vars[i].get()) {
      if (!callback(decl)) {
        return;
      }
    }
  }
}

// Internal iterator over each variable declared with the same
// name.
void Program::Impl::ForEachVariableWithName(
    const std::string &name,
    std::function<bool(const GlobalVarDecl *)> callback) {
  for (auto iterator_invalid = true; iterator_invalid; ) {
    iterator_invalid = false;
    const auto initial_num_vars = vars.size();
    for (auto range = name_to_var.equal_range(name);
         range.first != range.second;
         ++range.first) {
      if (!callback(range.first->second)) {
        return;
      } else if (initial_num_vars != vars.size()) {
        iterator_invalid = true;
        break;
      }
    }
  }
}

// Access memory, looking for a specific byte. Returns
// a reference to the found byte, or to an invalid byte.
Byte::Impl *Program::Impl::FindByte(uint64_t address) {
  uint64_t limit_address = 0;
  std::vector<Byte::Impl> *mapped_bytes = nullptr;

  auto it = bytes.upper_bound(address);
  if (it == bytes.end()) {
    if (bytes.empty()) {
      return nullptr;
    } else {
      auto rit = bytes.rbegin();
      if (rit->first == address) {
        limit_address = rit->first;
        mapped_bytes = &(rit->second);
      } else {
        return nullptr;
      }
    }
  } else {
    limit_address = it->first;
    mapped_bytes = &(it->second);
  }

  const auto base_address = limit_address - mapped_bytes->size();
  if (base_address <= address &&
      address <= limit_address) {
    return &((*mapped_bytes)[address - base_address]);
  } else {
    return nullptr;
  }
}

// Make a byte into the memory of the program.
llvm::Error Program::Impl::MapRange(const ByteRange &range) {

  if (range.begin >= range.end) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Empty or negative-sized byte range for mapped range "
        "starting at '%lx'",
        range.address);
  }

  const auto size = static_cast<uint64_t>(range.end - range.begin);

  // Look for overflow.
  //
  // TODO(pag): I think this is right.
  const auto max_addr = std::numeric_limits<uint64_t>::max();
  const auto end_address = range.address + size;
  if (((max_addr - (size - 1U)) < range.address) ||
      end_address <= range.address ||
      !end_address) {
    return llvm::createStringError(
        std::make_error_code(std::errc::bad_address),
        "Maximum address for mapped range starting at "
        "'%lx' is not representable",
        range.address);
  }

  // Make sure this range doesn't overlap with another one.
  for (auto existing : bytes) {
    auto existing_max_address = existing.first + 1U;
    auto existing_min_address =
        existing_max_address - existing.second.size();

    if (existing_min_address >= end_address) {
      break;

    } else if (existing_max_address <= range.address) {
      continue;

    } else {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Memory range [%lx, %lx) overlaps with an "
          "existing range [%lx, %lx)'",
          range.address, end_address,
          existing_min_address, existing_max_address);
    }
  }

  bool contains_funcs = false;

  // Go see if this range is agreeable with any of our function
  // declarations.
  for (const auto &decl : funcs) {
    if (range.address <= decl->address &&
        decl->address < end_address) {
      if (!range.is_executable) {
        return llvm::createStringError(
            std::make_error_code(std::errc::invalid_argument),
            "Memory range [%lx, %lx) is not marked as executable, "
            "and contains a declared function '%s' at %lx",
            range.address, end_address, decl->name.c_str(),
            decl->address);
      } else {
        contains_funcs = true;
      }
    }
  }

  // Make sure the range isn't mapped twice.
  auto &byte_impls = bytes[end_address];
  byte_impls.reserve(size);

  Byte::Impl byte_impl = {};
  byte_impl.is_readable = range.is_readable;
  byte_impl.is_writeable = range.is_writeable;
  byte_impl.is_executable = range.is_executable;

  for (auto b = range.begin; b < range.end; ++b) {
    byte_impl.value = *b;
    byte_impls.push_back(byte_impl);
  }

  if (contains_funcs) {
    for (const auto &decl : funcs) {
      if (range.address <= decl->address &&
          decl->address < end_address) {
        auto byte = FindByte(decl->address);
        byte->is_function_head = true;
      }
    }
  }

  // Go see if this range is agreeable with any of our global
  // variable declarations.
  for (const auto &decl : vars) {
    if (range.address <= decl->address &&
        decl->address < end_address) {
      auto byte = FindByte(decl->address);
      byte->is_variable_head = true;
      EmitEvent(kGlobalVariableDefined, decl->address);
    }
  }

  return llvm::Error::success();
}

// Map a custom stack range.
llvm::Error Program::Impl::MapStack(
    uint64_t base_address, uint64_t limit_address,
    uint64_t start_address) {
  if (has_initial_stack_pointer) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Program already has stack initialized");
  }


  if (!(base_address < start_address) ||
      !(start_address < limit_address)) {
    return llvm::createStringError(
        std::make_error_code(std::errc::bad_address),
        "Stack base address '%lx' must be less than the "
        "stack start address '%lx', which must be less than "
        "the stack limit address '%lx'",
        base_address, start_address, limit_address);
  }

  // Make sure this range doesn't overlap with another one.
  for (auto existing : bytes) {
    auto existing_max_address = existing.first + 1U;
    auto existing_min_address =
        existing_max_address - existing.second.size();

    if (existing_min_address >= limit_address) {
      break;

    } else if (existing_max_address <= base_address) {
      continue;

    } else {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Stack memory at [%lx, %lx) overlaps with an "
          "existing range [%lx, %lx)'",
          base_address, limit_address,
          existing_min_address, existing_max_address);
    }
  }

  // Go see if this range is agreeable with any of our function
  // declarations.
  for (const auto &decl : funcs) {
    if (base_address <= decl->address &&
        decl->address < limit_address) {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Stack memory range [%lx, %lx) contains a declared "
          "function '%s' at %lx",
          base_address, limit_address, decl->name.c_str(),
          decl->address);
    }
  }

  // Ditto for variables.
  for (const auto &decl : vars) {
    if (base_address <= decl->address &&
        decl->address < limit_address) {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Stack memory range [%lx, %lx) contains a declared "
          "global variable '%s' at %lx",
          base_address, limit_address, decl->name.c_str(),
          decl->address);
    }
  }

  // Make sure the range isn't mapped twice.
  auto &byte_impls = bytes[limit_address];
  byte_impls.reserve(limit_address - base_address);

  Byte::Impl byte_impl = {};
  byte_impl.is_readable = true;
  byte_impl.is_writeable = true;
  byte_impl.is_stack = true;
  byte_impl.is_undefined = true;

  for (auto b = base_address; b < limit_address; ++b) {
    byte_impls.push_back(byte_impl);
  }

  has_initial_stack_pointer = true;
  initial_stack_pointer = start_address;

  return llvm::Error::success();
}

Program::Program(void)
    : impl(std::make_shared<Impl>()) {}

Program::~Program(void) {}

// Declare a function in this view. This takes in a function
// declaration that will act as a sort of "template" for the
// declaration that we will make and will be owned by `Program`.
llvm::Error Program::DeclareFunction(
    const FunctionDecl &decl) const {
  return impl->DeclareFunction(decl);
}

// Internal iterator over all functions.
void Program::ForEachFunction(
    std::function<bool(const FunctionDecl *)> callback) const {
  return impl->ForEachFunction(callback);
}

// Search for a specific function by its address.
const FunctionDecl *Program::FindFunction(uint64_t address) const {
  return impl->FindFunction(address);
}

// Search for a specific function by its name.
// Call `callback` on each function with the given name.
void Program::ForEachFunctionWithName(
    const std::string &name,
    std::function<bool(const FunctionDecl *)> callback) const {
  impl->ForEachFunctionWithName(name, callback);
}

// Declare a variable in this view. This takes in a variable
// declaration that will act as a sort of "template" for the
// declaration that we will make and will be owned by `Program`.
llvm::Error Program::DeclareVariable(
    const GlobalVarDecl &decl_template) const {
  return impl->DeclareVariable(decl_template);
}

// Internal iterator over all vars.
void Program::ForEachVariable(
    std::function<bool(const GlobalVarDecl *)> callback) const {
  return impl->ForEachVariable(callback);
}

// Search for a specific variable by its address.
const GlobalVarDecl *Program::FindVariable(uint64_t address) const {
  return impl->FindVariable(address);
}

// Search for a specific variable by its name.
void Program::ForEachVariableWithName(
    const std::string &name,
    std::function<bool(const GlobalVarDecl *)> callback) const {
  impl->ForEachVariableWithName(name, callback);
}

// Access memory, looking for a specific byte. Returns
// the byte found, if any.
Byte Program::FindByte(uint64_t address) const {
  return Byte(address, impl->FindByte(address));
}

// Map a range of bytes into the program.
//
// This expects that none of the bytes already in that range
// are mapped. There are no requirements on the alignment
// of the mapped bytes.
llvm::Error Program::MapRange(const ByteRange &range) {
  return impl->MapRange(range);
}

// Map a custom stack range.
llvm::Error Program::MapStack(
    uint64_t base_address, uint64_t limit_address,
    uint64_t start_address) {
  return impl->MapStack(base_address, limit_address, start_address);
}

// Returns the initial stack pointer for functions to use.
llvm::Expected<uint64_t> Program::InitialStackPointer(void) const {
  if (impl->has_initial_stack_pointer) {
    return impl->initial_stack_pointer;
  } else {
    return llvm::createStringError(
        std::make_error_code(std::errc::not_enough_memory),
        "Stack memory range has not yet been initialized.");
  }
}

}  //  namespace anvill
