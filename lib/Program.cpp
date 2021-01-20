/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "anvill/Program.h"

#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Type.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Compat/VectorType.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <map>
#include <sstream>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "anvill/Decl.h"

namespace anvill {

// A byte's associated metadata. The metadata is updated throughout the
// lifting/decompiling process.
struct Byte::Meta {

  // True if there is a subsequent byte in the range that can be accessed.
  bool next_byte_is_in_range : 1;

  // True if there is a subsequent byte
  bool next_byte_starts_new_range : 1;

  // Is the value of this byte undefined? Our model of the stack
  // begins with all stack bytes, unless explicitly specified, as
  // undefined.
  bool is_undefined : 1;

  // Is this byte the beginning of a variable?
  bool is_variable_head : 1;

  // These require `is_executable` to be `true`.
  bool is_function_head : 1;

  // If `false`, then the implied semantic is that the byte will *never* be
  // writable. For example, if we're decompiling a snapshot or a core dump,
  // then the data associated with the ELF GOT/PLT sections would likely we
  // treated as being "constant" so that we could read through them.
  //
  // NOTE(pag): For jump tables to work most effectively, we expect the bytes
  //            that store the offsets/displacements/etc. to be marked as
  //            constants.
  bool is_writeable : 1;

  // NOTE(pag): We *only* treat a byte as possibly belonging to an instruction
  //            if `is_writable` is false. The semantic here is that we're
  //            unprepared to handle self-modifying code. Further, we don't
  //            want to treat bytes that might be in executable stacks as being
  //            code.
  bool is_executable : 1;

  // Do we have extended meta-data attached to this byte? This might include
  // things like devirtualization targets for calls through thunks or jump
  // tables.
  bool has_extended_meta : 1;

} __attribute__((packed));

static_assert(sizeof(Byte::Data) == sizeof(uint8_t),
              "Invalid packing of `struct Byte::Data`.");

static_assert(sizeof(Byte::Meta) == sizeof(uint8_t),
              "Invalid packing of `struct Byte::Meta`.");

enum ProgramEvent {
  kFunctionDeclared,
  kFunctionDefined,
  kGlobalVariableDeclared,
  kGlobalVariableDefined
};

// Default implementation of a program.
class Program::Impl : public std::enable_shared_from_this<Program::Impl> {
 public:
  llvm::Expected<FunctionDecl *>
  DeclareFunction(const FunctionDecl &decl_template, bool force);

  FunctionDecl *FindFunction(uint64_t address);

  llvm::Error DeclareVariable(const GlobalVarDecl &decl_template);

  GlobalVarDecl *FindVariable(uint64_t address);

  GlobalVarDecl *FindVariable(const std::string &name);

  llvm::Type *FindType(uint64_t address);

  std::pair<Byte::Data *, Byte::Meta *> FindByte(uint64_t address);

  std::tuple<Byte::Data *, Byte::Meta *, size_t> FindBytes(uint64_t address,
                                                           size_t size);

  llvm::Error MapRange(const ByteRange &range);

  void EmitEvent(ProgramEvent event, uint64_t address) {}

  // Mapping between addresses and names.
  std::multimap<uint64_t, std::string> ea_to_name;
  std::multimap<std::string, uint64_t> name_to_ea;

  // Declarations for the functions.
  bool funcs_are_sorted{true};
  std::vector<std::unique_ptr<FunctionDecl>> funcs;
  std::unordered_map<uint64_t, FunctionDecl *> ea_to_func;

  // Declarations for the variables.
  bool vars_are_sorted{true};
  std::vector<std::unique_ptr<GlobalVarDecl>> vars;
  std::unordered_map<uint64_t, GlobalVarDecl *> ea_to_var;

  // Values of all bytes mapped in memory, including additional
  // bits of metadata, and the address at which each byte is
  // loaded.
  //
  // The keys of the maps are the address of the last byte in
  // the range as represented in the mapped vector. The vectors
  // are sorted in order.
  std::map<uint64_t,
           std::pair<std::vector<Byte::Data>, std::vector<Byte::Meta>>>
      bytes;

  // Initial stack pointer.
  uint64_t initial_stack_pointer{0};
  bool has_initial_stack_pointer{false};
};

namespace {

static size_t EstimateSize(const remill::Arch *arch, llvm::Type *type) {
  switch (type->getTypeID()) {
    case llvm::Type::HalfTyID: return 2;
    case llvm::Type::FloatTyID: return 4;
    case llvm::Type::DoubleTyID: return 8;
    case llvm::Type::X86_FP80TyID: return 10;  // Assume no padding.
    case llvm::Type::X86_MMXTyID: return 8;

    case llvm::Type::IntegerTyID:
      return (type->getScalarSizeInBits() + 7u) / 8u;

    case llvm::Type::FP128TyID:
    case llvm::Type::PPC_FP128TyID: return 16;

    // Store a structure by storing the individual elements of the structure.
    //
    // NOTE(pag): We'll assume no padding.
    case llvm::Type::StructTyID: {
      auto struct_type = llvm::dyn_cast<llvm::StructType>(type);
      size_t size = 0;
      for (auto elem_type : struct_type->elements()) {
        size += EstimateSize(arch, elem_type);
      }
      return size;
    }

    // Build up the array store in the same was as we do with structures.
    case llvm::Type::ArrayTyID: {
      auto arr_type = llvm::dyn_cast<llvm::ArrayType>(type);
      const auto num_elems = arr_type->getNumElements();
      const auto elem_type = arr_type->getElementType();
      return num_elems * EstimateSize(arch, elem_type);
    }

    // Write pointers to memory by converting to the correct sized integer,
    // then storing that
    case llvm::Type::PointerTyID: return arch->address_size / 8u;

    // Build up the vector store in the nearly the same was as we do with arrays.
    case llvm::GetFixedVectorTypeId(): {
      auto vec_type = llvm::dyn_cast<llvm::FixedVectorType>(type);
      const auto num_elems = vec_type->getNumElements();
      const auto elem_type = vec_type->getElementType();
      return num_elems * EstimateSize(arch, elem_type);
    }

    case llvm::Type::VoidTyID:
    case llvm::Type::LabelTyID:
    case llvm::Type::MetadataTyID:
    case llvm::Type::TokenTyID:
    case llvm::Type::FunctionTyID:
    default:
      LOG(FATAL) << "Unable to produce IR sequence to store type "
                 << remill::LLVMThingToString(type) << " to memory";
      return 0;
  }
}

template <typename T>
static llvm::Error CheckValueDecl(const T &decl, llvm::LLVMContext &context,
                                  const char *desc, const FunctionDecl &tpl) {
  if (!decl.type) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Missing LLVM type information for %s "
        "in function declaration at %lx",
        desc, tpl.address);

  } else if (decl.type->isFunctionTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is a function type; "
        "did you mean to use a function pointer type?",
        desc, tpl.address);

  } else if (decl.type->isVoidTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is a void type; "
        "did you mean to use a void pointer type, or to "
        "exclude it entirely?",
        desc, tpl.address);

  } else if (&(decl.type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is associated "
        "with a different LLVM context than the function's "
        "architecture",
        desc, tpl.address);

  } else if (decl.reg && decl.mem_reg) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "A %s cannot be resident in both a "
        "register (%s) and a memory location (%s + %ld) in "
        "function declaration at %lx",
        desc, decl.reg->name.c_str(), decl.mem_reg->name.c_str(),
        decl.mem_offset, tpl.address);

  } else if (decl.reg && &(decl.reg->type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is associated "
        "with a different LLVM context than the %s's "
        "register location",
        desc, tpl.address, desc);

  } else if (decl.mem_reg && &(decl.mem_reg->type->getContext()) != &context) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for %s "
        "in function declaration at %lx is associated "
        "with a different LLVM context than the %s's "
        "memory location base register",
        desc, tpl.address, desc);

  } else if (decl.mem_reg && !decl.mem_reg->type->isIntegerTy()) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Type of memory base register of %s in function "
        "declaration at %lx must be integral",
        desc, tpl.address);
  }

  if (decl.reg && decl.type) {
    auto reg_size = EstimateSize(tpl.arch, decl.reg->type);
    auto type_size = EstimateSize(tpl.arch, decl.type);
    if (reg_size < type_size) {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Size of register %s of %s in function "
          "declaration at %lx is too small (%lu bytes) for "
          "value of size %lu bytes",
          decl.reg->name.c_str(), desc, tpl.address, reg_size, type_size);
    }
  }

  return llvm::Error::success();
}

}  // namespace

bool Byte::IsWriteableImpl(void) const {
  return meta->is_writeable;
}

bool Byte::IsExecutableImpl(void) const {
  return meta->is_executable;
}

bool Byte::IsUndefinedImpl(void) const {
  return meta->is_undefined;
}

bool Byte::SetUndefinedImpl(bool is_undef) const {
  if (meta->is_function_head && !meta->is_variable_head) {
    meta->is_undefined = is_undef;
    return true;
  } else {
    return false;
  }
}

// Convert this byte sequence to a string.
std::string_view ByteSequence::ToString(void) const {
  if (first_data) {
    return std::string_view(reinterpret_cast<const char *>(first_data), size);
  } else {
    return std::string_view();
  }
}

// Extract a substring of bytes from this byte sequence.
std::string_view ByteSequence::Substring(uint64_t ea, size_t seq_size) const {
  if (const auto offset = ea - address; address <= ea && offset < size) {
    std::string_view data(reinterpret_cast<const char *>(first_data), size);
    if (auto max_ea = ea + seq_size; max_ea > (address + size)) {
      return data.substr(offset, size - offset);
    } else {
      return data.substr(offset, seq_size);
    }
  } else {
    return std::string_view();
  }
}

// Index a specific byte within this sequence. Indexing is based off of the
// byte's address.
Byte ByteSequence::operator[](uint64_t ea) const {
  if (const auto offset = ea - address; address <= ea && offset < size) {
    return Byte(ea, &(first_data[offset]), &(first_meta[offset]));
  } else {
    return Byte();
  }
}

// Declare a function in this view.
llvm::Expected<FunctionDecl *>
Program::Impl::DeclareFunction(const FunctionDecl &tpl, bool force) {

  const auto [data, meta] = FindByte(tpl.address);
  if (meta) {
    (void) data;
    if (!meta->is_executable) {
      return llvm::createStringError(
          std::make_error_code(std::errc::bad_address),
          "Function at address '%lx' is not executable.", tpl.address);
    }
  }

  if (auto existing_decl = FindFunction(tpl.address); existing_decl && !force) {
    return llvm::createStringError(
        std::make_error_code(std::errc::address_in_use),
        "A function is already declared at '%lx'", existing_decl->address);
  }

  if (!tpl.arch) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "Missing architecture for function declared at '%lx'", tpl.address);
  }

  auto &context = *(tpl.arch->context);

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
          tpl.address, pc_reg_name.data());
    }
  } else {
    return llvm::createStringError(
        std::make_error_code(std::errc::operation_canceled),
        "Cannot find register information for program counter "
        "register '%s'; has the semantics module for the architecture "
        "associated with the function declaration at '%lx' been loaded?",
        pc_reg_name.data(), tpl.address);
  }

  auto err = CheckValueDecl(return_address, context, "return address", tpl);
  if (err) {
    return std::move(err);
  }

  for (auto &param : tpl.params) {
    err = CheckValueDecl(param, context, "parameter", tpl);
    if (err) {
      return std::move(err);
    }
  }

  for (auto &ret : tpl.returns) {
    err = CheckValueDecl(ret, context, "return value", tpl);
    if (err) {
      return std::move(err);
    }
  }

  if (!tpl.return_stack_pointer) {
    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "The return stack pointer base register must be provided", tpl.address);

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
          sp_reg_name.data(), remill::GetArchName(tpl.arch->arch_name).data(),
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
    llvm::SmallVector<llvm::Type *, 8> ret_types;
    for (auto &ret_val : tpl.returns) {
      ret_types.push_back(ret_val.type);
    }
    ret_type = llvm::StructType::get(context, ret_types, true);
  }

  llvm::SmallVector<llvm::Type *, 8> param_types;
  for (auto &param_val : tpl.params) {
    param_types.push_back(param_val.type);
  }

  const auto func_type =
      llvm::FunctionType::get(ret_type, param_types, tpl.is_variadic);
  if (tpl.type && tpl.type != func_type) {
    LOG(ERROR) << remill::LLVMThingToString(tpl.type);
    LOG(ERROR) << remill::LLVMThingToString(func_type);

    return llvm::createStringError(
        std::make_error_code(std::errc::invalid_argument),
        "LLVM type information for function declaration at '%lx' "
        "should not be manually specified",
        tpl.address);
  }

  std::unique_ptr<FunctionDecl> decl(new FunctionDecl(std::move(tpl)));
  const auto decl_ptr = decl.get();
  decl_ptr->return_address = return_address;
  decl_ptr->owner = this;
  decl->type = func_type;

  if (funcs_are_sorted && !funcs.empty() &&
      funcs.back()->address > decl->address) {
    funcs_are_sorted = false;
  }

  funcs.emplace_back(std::move(decl));
  ea_to_func.emplace(decl_ptr->address, decl_ptr);

  if (meta) {
    meta->is_function_head = true;
    EmitEvent(kFunctionDefined, decl_ptr->address);
  } else {
    EmitEvent(kFunctionDeclared, decl_ptr->address);
  }

  return decl_ptr;
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

// Declare a variable in this view.
llvm::Error Program::Impl::DeclareVariable(const GlobalVarDecl &tpl) {


  if (auto existing_decl = FindVariable(tpl.address); existing_decl) {
    return llvm::createStringError(
        std::make_error_code(std::errc::address_in_use),
        "A variable is already declared at '%lx'", existing_decl->address);
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

  auto [data, meta] = FindByte(tpl.address);
  std::unique_ptr<GlobalVarDecl> decl(new GlobalVarDecl(tpl));

  const auto decl_ptr = decl.get();
  decl_ptr->owner = this;

  if (vars_are_sorted && !vars.empty() &&
      vars.back()->address > decl->address) {
    vars_are_sorted = false;
  }

  vars.emplace_back(std::move(decl));
  ea_to_var.emplace(decl_ptr->address, decl_ptr);

  if (meta) {
    (void) data;
    meta->is_variable_head = true;
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

// Lookup the type that corresponds to an address
llvm::Type *Program::Impl::FindType(uint64_t address) {

  //FIXME (Carson) this is just for debugging
  uint64_t hit_count = 0;
  llvm::Type *ret = nullptr;
  for (auto &curr_func : funcs) {
    if (auto match = curr_func->reg_info.find(address);
        match != curr_func->reg_info.end()) {
      hit_count += 1;
      ret = match->second.type;
    }
  }
  assert(hit_count == 1);
  return ret;
}

// Access memory, looking for a specific byte. Returns
// a reference to the found byte, or to an invalid byte.
std::pair<Byte::Data *, Byte::Meta *>
Program::Impl::FindByte(uint64_t address) {
  uint64_t limit_address = 0;
  std::vector<Byte::Data> *mapped_data = nullptr;
  std::vector<Byte::Meta> *mapped_meta = nullptr;

  auto it = bytes.upper_bound(address);
  if (it == bytes.end()) {
    const auto rit = bytes.rbegin();
    if (rit == bytes.rend()) {
      return {nullptr, nullptr};

    } else if (rit->first == address) {
      limit_address = rit->first;
      mapped_data = &(rit->second.first);
      mapped_meta = &(rit->second.second);
    } else {
      return {nullptr, nullptr};
    }

  } else {
    limit_address = it->first;
    mapped_data = &(it->second.first);
    mapped_meta = &(it->second.second);
  }

  const auto base_address = limit_address - mapped_data->size();
  if (base_address <= address && address < limit_address) {
    const auto offset = address - base_address;
    return {&((*mapped_data)[offset]), &((*mapped_meta)[offset])};
  } else {
    return {nullptr, nullptr};
  }
}

// Find a sequence of bytes within the same mapped range starting at
// `address` and including as many bytes fall within the range up to
// but not including `address+size`.
std::tuple<Byte::Data *, Byte::Meta *, size_t>
Program::Impl::FindBytes(uint64_t address, size_t size) {
  if (!size) {
    return {nullptr, nullptr, 0};
  }

  uint64_t limit_address = 0;
  std::vector<Byte::Data> *mapped_data = nullptr;
  std::vector<Byte::Meta> *mapped_meta = nullptr;

  auto it = bytes.upper_bound(address);
  if (it == bytes.end()) {
    const auto rit = bytes.rbegin();
    if (rit == bytes.rend()) {
      return {nullptr, nullptr, 0};

    } else if (rit->first == address) {
      limit_address = rit->first;
      mapped_data = &(rit->second.first);
      mapped_meta = &(rit->second.second);
    } else {
      return {nullptr, nullptr, 0};
    }

  } else {
    limit_address = it->first;
    mapped_data = &(it->second.first);
    mapped_meta = &(it->second.second);
  }

  const auto base_address = limit_address - mapped_data->size();
  if (base_address <= address && address < limit_address) {
    const auto offset = address - base_address;
    if (size > mapped_data->size()) {
      size = mapped_data->size();
    }
    return {&((*mapped_data)[offset]), &((*mapped_meta)[offset]), size};

  } else {
    return {nullptr, nullptr, 0};
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
  if (((max_addr - (size - 1u)) < range.address) ||
      end_address <= range.address || !end_address) {
    return llvm::createStringError(
        std::make_error_code(std::errc::bad_address),
        "Maximum address for mapped range starting at "
        "'%lx' is not representable",
        range.address);
  }

  // Make sure this range doesn't overlap with another one.
  for (const auto &existing : bytes) {
    auto existing_max_address = existing.first;
    auto existing_min_address =
        existing_max_address - existing.second.first.size();

    if (existing_min_address >= end_address) {
      break;

    } else if (existing_max_address <= range.address) {
      continue;

    } else {
      return llvm::createStringError(
          std::make_error_code(std::errc::invalid_argument),
          "Memory range [%lx, %lx) overlaps with an "
          "existing range [%lx, %lx)'",
          range.address, end_address, existing_min_address,
          existing_max_address);
    }
  }

  bool contains_funcs = false;

  // Go see if this range is agreeable with any of our function
  // declarations.
  for (const auto &decl : funcs) {
    if (range.address <= decl->address && decl->address < end_address) {
      if (!range.is_executable) {
        return llvm::createStringError(
            std::make_error_code(std::errc::invalid_argument),
            "Memory range [%lx, %lx) is not marked as executable, "
            "and contains a declared function at %lx",
            range.address, end_address, decl->address);
      } else {
        contains_funcs = true;
      }
    }
  }

  // Make sure the range isn't mapped twice.
  auto &byte_impls = bytes[end_address];
  byte_impls.first.reserve(size);

  Byte::Meta meta_impl = {};
  meta_impl.is_writeable = range.is_writeable;
  meta_impl.is_executable = range.is_executable;
  meta_impl.next_byte_is_in_range = true;

  byte_impls.first.insert(byte_impls.first.end(), range.begin, range.end);
  byte_impls.second.insert(byte_impls.second.end(), size, meta_impl);
  byte_impls.second.back().next_byte_is_in_range = false;

  if (contains_funcs) {
    for (const auto &decl : funcs) {
      if (range.address <= decl->address && decl->address < end_address) {
        if (auto [data, meta] = FindByte(decl->address); meta) {
          (void) data;
          meta->is_function_head = true;
          EmitEvent(kFunctionDefined, decl->address);
        }
      }
    }
  }

  // Go see if this range is agreeable with any of our global
  // variable declarations.
  for (const auto &decl : vars) {
    if (range.address <= decl->address && decl->address < end_address) {
      if (auto [data, meta] = FindByte(decl->address); meta) {
        (void) data;
        meta->is_variable_head = true;
        EmitEvent(kGlobalVariableDefined, decl->address);
      }
    }
  }

  // Mark the last byte in the previous range, if it exists, as having a
  // subsequent byte.
  if (auto [prev_data, prev_meta] = FindByte(range.address - 1);
      prev_meta && range.address) {
    (void) prev_data;
    prev_meta->next_byte_is_in_range = false;
    prev_meta->next_byte_starts_new_range = true;
  }

  return llvm::Error::success();
}

Program::Program(void) : impl(std::make_shared<Impl>()) {}

Program::~Program(void) {}

// Declare a function in this view. This takes in a function
// declaration that will act as a sort of "template" for the
// declaration that we will make and will be owned by `Program`.
llvm::Expected<FunctionDecl *>
Program::DeclareFunction(const FunctionDecl &decl, bool force) const {
  return impl->DeclareFunction(decl, force);
}

// Internal iterator over all functions.
void Program::ForEachFunction(
    std::function<bool(const FunctionDecl *)> callback) const {
  if (!impl->funcs_are_sorted) {
    std::sort(impl->vars.begin(), impl->vars.end(),
              [](const std::unique_ptr<GlobalVarDecl> &a,
                 const std::unique_ptr<GlobalVarDecl> &b) {
                return a->address < b->address;
              });
    impl->funcs_are_sorted = true;
  }
  for (size_t i = 0; i < impl->funcs.size(); ++i) {
    if (const auto decl = impl->funcs[i].get()) {
      if (!callback(decl)) {
        return;
      }
    }
  }
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
  const auto func_it_end = impl->ea_to_func.end();
  for (auto it = impl->name_to_ea.find(name), it_end = impl->name_to_ea.end();
       it != it_end && it->first == name; ++it) {
    if (auto func_it = impl->ea_to_func.find(it->second);
        func_it != func_it_end) {
      if (!callback(func_it->second)) {
        return;
      }
    }
  }
}

// Apply a function `cb` to each name of the address `address`.
void Program::ForEachNameOfAddress(
    uint64_t ea, std::function<bool(const std::string &, const FunctionDecl *,
                                    const GlobalVarDecl *)>
                     callback) const {

  const auto func = FindFunction(ea);
  const auto var = FindVariable(ea);

  for (auto it = impl->ea_to_name.find(ea), it_end = impl->ea_to_name.end();
       it != it_end && it->first == ea; ++it) {
    if (!callback(it->second, func, var)) {
      return;
    }
  }
}

// Apply a function `cb` to each name of the address `address`.
void Program::ForEachAddressOfName(
    const std::string &name,
    std::function<bool(uint64_t, const FunctionDecl *, const GlobalVarDecl *)>
        callback) const {

  for (auto it = impl->name_to_ea.find(name), it_end = impl->name_to_ea.end();
       it != it_end && it->first == name; ++it) {
    const auto ea = it->second;
    const auto func = FindFunction(ea);
    const auto var = FindVariable(ea);
    if (!callback(ea, func, var)) {
      return;
    }
  }
}

// Apply a function `cb` to each address/name pair.
void Program::ForEachNamedAddress(
    std::function<bool(uint64_t, const std::string &, const FunctionDecl *,
                       const GlobalVarDecl *)>
        callback) const {
  for (auto it = impl->ea_to_name.begin(), it_end = impl->ea_to_name.end();
       it != it_end; ++it) {
    const auto ea = it->first;
    const auto func = FindFunction(ea);
    const auto var = FindVariable(ea);
    if (!callback(ea, it->second, func, var)) {
      return;
    }
  }
}

// Add a name to an address.
void Program::AddNameToAddress(const std::string &name,
                               uint64_t address) const {
  if (!name.empty() && address) {
    impl->name_to_ea.emplace(name, address);
    impl->ea_to_name.emplace(address, name);
  }
}

// Declare a variable in this view. This takes in a variable
// declaration that will act as a sort of "template" for the
// declaration that we will make and will be owned by `Program`.
llvm::Error Program::DeclareVariable(const GlobalVarDecl &decl) const {
  return impl->DeclareVariable(decl);
}

// Internal iterator over all vars.
void Program::ForEachVariable(
    std::function<bool(const GlobalVarDecl *)> callback) const {
  if (!impl->vars_are_sorted) {
    std::sort(impl->vars.begin(), impl->vars.end(),
              [](const std::unique_ptr<GlobalVarDecl> &a,
                 const std::unique_ptr<GlobalVarDecl> &b) {
                return a->address < b->address;
              });
    impl->vars_are_sorted = true;
  }

  // NOTE(pag): Size of variables may change.
  for (size_t i = 0; i < impl->vars.size(); ++i) {
    if (const auto decl = impl->vars[i].get(); decl) {
      if (!callback(decl)) {
        return;
      }
    }
  }
}

// Search for a specific variable by its address.
const GlobalVarDecl *Program::FindVariable(uint64_t address) const {
  return impl->FindVariable(address);
}

// Search for a specific variable by its name.
void Program::ForEachVariableWithName(
    const std::string &name,
    std::function<bool(const GlobalVarDecl *)> callback) const {
  const auto var_it_end = impl->ea_to_var.end();
  for (auto it = impl->name_to_ea.find(name), it_end = impl->name_to_ea.end();
       it != it_end && it->first == name; ++it) {
    if (auto var_it = impl->ea_to_var.find(it->second); var_it != var_it_end) {
      if (!callback(var_it->second)) {
        return;
      }
    }
  }
}

// Lookup type corresponding to an address
llvm::Type *Program::FindType(uint64_t address) const {
  return impl->FindType(address);
}

// Access memory, looking for a specific byte. Returns
// the byte found, if any.
Byte Program::FindByte(uint64_t address) const {
  auto [data, meta] = impl->FindByte(address);
  return Byte(address, data, meta);
}

// Find the next byte.
Byte Program::FindNextByte(Byte byte) const {
  if (byte.meta) {
    if (byte.meta->next_byte_is_in_range) {
      return Byte(byte.addr + 1u, &(byte.data[1]), &(byte.meta[1]));

    } else if (byte.meta->next_byte_starts_new_range) {
      return FindByte(byte.addr + 1u);
    }
  }
  return Byte(byte.addr + 1u, nullptr, nullptr);
}

// Find a sequence of bytes within the same mapped range starting at
// `address` and including as many bytes fall within the range up to
// but not including `address+size`.
ByteSequence Program::FindBytes(uint64_t address, size_t size) const {
  auto [data, meta, found_size] = impl->FindBytes(address, size);
  return ByteSequence(address, data, meta, found_size);
}

// Map a range of bytes into the program.
//
// This expects that none of the bytes already in that range
// are mapped. There are no requirements on the alignment
// of the mapped bytes.
llvm::Error Program::MapRange(const ByteRange &range) {
  return impl->MapRange(range);
}

Program::Program(void *opaque)
    : impl(reinterpret_cast<Program::Impl *>(opaque)->shared_from_this()) {}

llvm::Expected<Program> Program::Containing(const FunctionDecl *decl) {
  if (!decl->owner) {
    return llvm::createStringError(
        std::errc::invalid_argument,
        "The function at '%08x'is not valid or does not have an owner.",
        decl->address);
  } else {
    return Program(decl->owner);
  }
}

llvm::Expected<Program> Program::Containing(const GlobalVarDecl *decl) {
  if (!decl->owner) {
    return llvm::createStringError(
        std::errc::invalid_argument,
        "The variable at '%08x' is not valid or does not have an owner.",
        decl->address);
  } else {
    return Program(decl->owner);
  }
}

}  //  namespace anvill
