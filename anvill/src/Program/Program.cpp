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

#include "Program.h"

#include <glog/logging.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/MemoryBuffer.h>

#include <llvm_utils/TypeParser.h>

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

#include "Program.h"
#include "Decl/Decl.h"

namespace anvill {

Program::Ptr Program::CreateFromSpecFile(const remill::Arch *arch, llvm::LLVMContext &context, const std::filesystem::path &spec_file_path) {
  try {
    return Ptr(new Program(arch, context, spec_file_path));

  } catch (const std::runtime_error &e) {
    LOG(FATAL) << e.what();

  } catch (const std::bad_alloc &) {
    LOG(FATAL) << "Failed to allocate the Program object";
  }

  return nullptr;
}

// Declare a function in this view.
llvm::Expected<FunctionDecl *> Program::DeclareFunction(const FunctionDecl &tpl, bool force) {

  const auto [data, meta] = FindByteTuple(tpl.address);
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
    //EmitEvent(kFunctionDefined, decl_ptr->address);
  } else {
    //EmitEvent(kFunctionDeclared, decl_ptr->address);
  }

  return decl_ptr;
}

// Search for a specific function.
FunctionDecl *Program::FindFunction(uint64_t address) {
  const auto it = ea_to_func.find(address);
  if (it != ea_to_func.end()) {
    return it->second;
  } else {
    return nullptr;
  }
}

bool Program::TryGetControlFlowRedirection(std::uint64_t &destination,
                                                 std::uint64_t address) {
  destination = 0U;

  auto it = ctrl_flow_redirections.find(address);
  if (it == ctrl_flow_redirections.end()) {
    return false;
  }

  destination = it->second;
  return true;
}

void Program::AddControlFlowRedirection(std::uint64_t from,
                                              std::uint64_t to) {
  CHECK_EQ(ctrl_flow_redirections.count(from), 0U);
  ctrl_flow_redirections.insert({from, to});
}

// Declare a variable in this view.
llvm::Error Program::DeclareVariable(const GlobalVarDecl &tpl) {


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

  auto [data, meta] = FindByteTuple(tpl.address);
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
    //EmitEvent(kGlobalVariableDefined, decl_ptr->address);
  } else {
    //EmitEvent(kGlobalVariableDeclared, decl_ptr->address);
  }

  return llvm::Error::success();
}

// Search for a specific variable.
GlobalVarDecl *Program::FindVariable(uint64_t address) {
  const auto it = ea_to_var.find(address);
  if (it != ea_to_var.end()) {
    return it->second;
  } else {
    return nullptr;
  }
}

GlobalVarDecl *Program::FindInVariable(uint64_t address,
                                             const llvm::DataLayout &layout) {

  GlobalVarDecl *closest_match = nullptr;
  for (auto [var_address, var] : ea_to_var) {
    if (var_address <= address) {
      closest_match = var;
    } else {

      // NOTE(artem): ea_to_var is a sorted map, so we can quit once we find and address out of range
      break;
    }
  }

  // the address is not in the range of variable map
  if (!closest_match) {
    return nullptr;
  }

  // this matched an exact address of a variable; return it
  if (closest_match->address == address) {
    return closest_match;
  }

  // if there is no type, we can't really see if `address` is inside the type size
  if (!closest_match->type) {
    return nullptr;
  }

  // lets find out how big this type is (including padding)
  const auto type_size =
      static_cast<uint64_t>(layout.getTypeAllocSize(closest_match->type));

  // make sure to clamp the address range to what our target actually uses
  auto address_mask = std::numeric_limits<uint64_t>::max();
  if (layout.getPointerSizeInBits() == 32) {

    // clamp to 32 bits if needed
    address_mask >>= 32u;
  }

  const auto address_max = address_mask & (closest_match->address + type_size);

  if (address_max < closest_match->address || address_max < type_size) {

    // overflow occurred: address + type size overflows address space limits
    // TODO(artem): there is a chance that the reference could still be valid if
    // ea is between second->address and the max for the address space
    return nullptr;
  }

  if (closest_match->address <= address && address < address_max) {

    // The address referenced into the middle of the type
    return closest_match;
  } else {

    // the address is outside this type's allocated bounds
    return nullptr;
  }
}

// Access memory, looking for a specific byte. Returns
// a reference to the found byte, or to an invalid byte.
std::pair<Byte::Data *, Byte::Meta *>
Program::FindByteTuple(uint64_t address) {
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

std::tuple<Byte::Data *, Byte::Meta *, size_t, uint64_t>
Program::FindBytesContainingTuple(uint64_t address) {
  uint64_t limit_address = 0;
  std::vector<Byte::Data> *mapped_data = nullptr;
  std::vector<Byte::Meta> *mapped_meta = nullptr;

  auto it = bytes.upper_bound(address);
  if (it == bytes.end()) {
    const auto rit = bytes.rbegin();
    if (rit == bytes.rend()) {
      return {nullptr, nullptr, 0, 0};

    } else if (rit->first == address) {
      limit_address = rit->first;
      mapped_data = &(rit->second.first);
      mapped_meta = &(rit->second.second);
    } else {
      return {nullptr, nullptr, 0, 0};
    }

  } else {
    limit_address = it->first;
    mapped_data = &(it->second.first);
    mapped_meta = &(it->second.second);
  }

  const auto base_address = limit_address - mapped_data->size();
  if (base_address <= address && address < limit_address) {
    return {&((*mapped_data)[0]), &((*mapped_meta)[0]), mapped_data->size(),
            base_address};
  } else {
    return {nullptr, nullptr, 0, 0};
  }
}

// Find a sequence of bytes within the same mapped range starting at
// `address` and including as many bytes fall within the range up to
// but not including `address+size`.
// TODO(artem): This code shares much in common with FindBytesContaining.
// And it can be reimplemented in terms of FindBytesContaining
std::tuple<Byte::Data *, Byte::Meta *, size_t>
Program::FindBytesTuple(uint64_t address, size_t size) {
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
llvm::Error Program::MapRange(const ByteRange &range) {

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
        if (auto [data, meta] = FindByteTuple(decl->address); meta) {
          (void) data;
          meta->is_function_head = true;
          //EmitEvent(kFunctionDefined, decl->address);
        }
      }
    }
  }

  // Go see if this range is agreeable with any of our global
  // variable declarations.
  for (const auto &decl : vars) {
    if (range.address <= decl->address && decl->address < end_address) {
      if (auto [data, meta] = FindByteTuple(decl->address); meta) {
        (void) data;
        meta->is_variable_head = true;
        //EmitEvent(kGlobalVariableDefined, decl->address);
      }
    }
  }

  // Mark the last byte in the previous range, if it exists, as having a
  // subsequent byte.
  if (auto [prev_data, prev_meta] = FindByteTuple(range.address - 1);
      prev_meta && range.address) {
    (void) prev_data;
    prev_meta->next_byte_is_in_range = false;
    prev_meta->next_byte_starts_new_range = true;
  }

  return llvm::Error::success();
}

Program::Program(const remill::Arch *arch, llvm::LLVMContext &context, const std::filesystem::path &spec_file_path) {
  auto input_path = spec_file_path.string();
  if (input_path == "/dev/stdin") {
    input_path = "-";
  }

  auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(input_path);
  if (remill::IsError(maybe_buff)) {
    std::stringstream buffer;
    buffer << "Unable to read JSON spec file '" << input_path
               << "': " << remill::GetErrorString(maybe_buff);

    throw std::runtime_error(buffer.str());
  }

  const std::unique_ptr<llvm::MemoryBuffer> &buff = remill::GetReference(maybe_buff);

  auto maybe_json = llvm::json::parse(buff->getBuffer());
  if (remill::IsError(maybe_json)) {
    std::stringstream buffer;
    buffer << "Unable to parse JSON spec file '" << input_path
               << "': " << remill::GetErrorString(maybe_json);

    throw std::runtime_error(buffer.str());
  }

  llvm::json::Value &json = remill::GetReference(maybe_json);
  const auto spec = json.getAsObject();
  if (!spec) {
    std::stringstream buffer;
    buffer << "JSON spec file '" << input_path
               << "' must contain a single object.";

    throw std::runtime_error(buffer.str());
  }

  if (!ParseSpec(arch, context, spec, input_path)) {
    throw std::runtime_error("Failed to parse the spec file");
  }
}

Program::~Program(void) {}

// Internal iterator over all functions.
void Program::ForEachFunction(
    std::function<bool(const FunctionDecl *)> callback) {
  if (!funcs_are_sorted) {
    std::sort(vars.begin(), vars.end(),
              [](const std::unique_ptr<GlobalVarDecl> &a,
                 const std::unique_ptr<GlobalVarDecl> &b) {
                return a->address < b->address;
              });
    funcs_are_sorted = true;
  }
  for (size_t i = 0; i < funcs.size(); ++i) {
    if (const auto decl = funcs[i].get()) {
      if (!callback(decl)) {
        return;
      }
    }
  }
}

// Search for a specific function by its name.
// Call `callback` on each function with the given name.
void Program::ForEachFunctionWithName(
    const std::string &name,
    std::function<bool(const FunctionDecl *)> callback) {
  const auto func_it_end = ea_to_func.end();
  for (auto it = name_to_ea.find(name), it_end = name_to_ea.end();
       it != it_end && it->first == name; ++it) {
    if (auto func_it = ea_to_func.find(it->second);
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
                     callback) {

  const auto func = FindFunction(ea);
  const auto var = FindVariable(ea);

  for (auto it = ea_to_name.find(ea), it_end = ea_to_name.end();
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
        callback) {

  for (auto it = name_to_ea.find(name), it_end = name_to_ea.end();
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
        callback) {
  for (auto it = ea_to_name.begin(), it_end = ea_to_name.end();
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
                               uint64_t address) {
  if (!name.empty() && address) {
    name_to_ea.emplace(name, address);
    ea_to_name.emplace(address, name);
  }
}

// Internal iterator over all vars.
void Program::ForEachVariable(
    std::function<bool(const GlobalVarDecl *)> callback) {
  if (!vars_are_sorted) {
    std::sort(vars.begin(), vars.end(),
              [](const std::unique_ptr<GlobalVarDecl> &a,
                 const std::unique_ptr<GlobalVarDecl> &b) {
                return a->address < b->address;
              });
    vars_are_sorted = true;
  }

  // NOTE(pag): Size of variables may change.
  for (size_t i = 0; i < vars.size(); ++i) {
    if (const auto decl = vars[i].get(); decl) {
      if (!callback(decl)) {
        return;
      }
    }
  }
}

// Search for a specific variable by its name.
void Program::ForEachVariableWithName(
    const std::string &name,
    std::function<bool(const GlobalVarDecl *)> callback) {
  const auto var_it_end = ea_to_var.end();
  for (auto it = name_to_ea.find(name), it_end = name_to_ea.end();
       it != it_end && it->first == name; ++it) {
    if (auto var_it = ea_to_var.find(it->second); var_it != var_it_end) {
      if (!callback(var_it->second)) {
        return;
      }
    }
  }
}

// Access memory, looking for a specific byte. Returns
// the byte found, if any.
Byte Program::FindByte(uint64_t address) {
  auto [data, meta] = FindByteTuple(address);
  return Byte(address, data, meta);
}

// Find which byte sequence (defined in the spec) has the provided `address`
ByteSequence Program::FindBytesContaining(uint64_t address) {
  auto [data, meta, found_size, base_address] =
      FindBytesContainingTuple(address);
  return ByteSequence(base_address, data, meta, found_size);
}

// Find the next byte.
Byte Program::FindNextByte(Byte byte) {
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
ByteSequence Program::FindBytes(uint64_t address, size_t size) {
  auto [data, meta, found_size] = FindBytesTuple(address, size);
  return ByteSequence(address, data, meta, found_size);
}

bool Program::ParseSpec(const remill::Arch *arch, llvm::LLVMContext &context, llvm::json::Object *spec, const std::string &input_file) {
  auto num_funcs = 0;
  if (auto funcs = spec->getArray("functions")) {
    for (llvm::json::Value &func : *funcs) {
      if (auto func_obj = func.getAsObject()) {
        if (!ParseFunction(arch, context, func_obj, input_file)) {
          return false;
        } else {
          ++num_funcs;
        }
      } else {
        LOG(ERROR) << "Non-JSON object in 'functions' array of spec file '"
                   << input_file << "'";
        return false;
      }
    }
  } else if (spec->find("functions") != spec->end()) {
    LOG(ERROR) << "Non-JSON array value for 'functions' in spec file '"
               << input_file << "'";
    return false;
  }

  if (auto redirection_list = spec->getArray("control_flow_redirections")) {
    if (!ParseControlFlowRedirection(*redirection_list, input_file)) {
      LOG(ERROR)
          << "Failed to parse the 'control_flow_redirections' section in spec file '"
          << input_file << "'";

      return false;
    }

  } else if (spec->find("control_flow_redirections") != spec->end()) {
    LOG(ERROR)
        << "Non-JSON array value for 'control_flow_redirections' in spec file '"
        << input_file << "'";
    return false;
  }

  if (auto vars = spec->getArray("variables")) {
    for (llvm::json::Value &var : *vars) {
      if (auto var_obj = var.getAsObject()) {
        if (!ParseVariable(arch, context, var_obj, input_file)) {
          return false;
        }
      } else {
        LOG(ERROR) << "Non-JSON object in 'variables' array of spec file '"
                   << input_file << "'";
        return false;
      }
    }
  } else if (spec->find("variables") != spec->end()) {
    LOG(ERROR) << "Non-JSON array value for 'variables' in spec file '"
               << input_file << "'";
    return false;
  }

  if (auto ranges = spec->getArray("memory")) {
    for (llvm::json::Value &range : *ranges) {
      if (auto range_obj = range.getAsObject()) {
        if (!ParseRange(range_obj, input_file)) {
          return false;
        }
      } else {
        LOG(ERROR) << "Non-JSON object in 'bytes' array of spec file '"
                   << input_file << "'";
        return false;
      }
    }
  } else if (spec->find("memory") != spec->end()) {
    LOG(ERROR) << "Non-JSON array value for 'memory' in spec file '"
               << input_file << "'";
    return false;
  }

  if (auto symbols = spec->getArray("symbols")) {
    for (llvm::json::Value &maybe_ea_name : *symbols) {
      if (auto ea_name = maybe_ea_name.getAsArray(); ea_name) {
        if (ea_name->size() != 2) {
          LOG(ERROR) << "Symbol entry doesn't have two values in spec file '"
                     << input_file << "'";
          return false;
        }
        auto &maybe_ea = ea_name->operator[](0);
        auto &maybe_name = ea_name->operator[](1);

        if (auto ea = maybe_ea.getAsInteger(); ea) {
          if (auto name = maybe_name.getAsString(); name) {
            AddNameToAddress(name->str(),
                                     static_cast<uint64_t>(ea.getValue()));
          } else {
            LOG(ERROR)
                << "Second value in symbol entry must be a string in spec file '"
                << input_file << "'";
            return false;
          }
        } else {
          LOG(ERROR)
              << "First value in symbol entry must be an integer in spec file '"
              << input_file << "'";
          return false;
        }
      } else {
        LOG(ERROR)
            << "Expected array entries inside of 'symbols' array in spec file '"
            << input_file << "'";
        return false;
      }
    }
  } else if (spec->find("symbols") != spec->end()) {
    LOG(ERROR) << "Non-JSON array value for 'symbols' in spec file '"
               << input_file << "'";
    return false;
  }

  return true;
}

bool Program::ParseFunction(const remill::Arch *arch, llvm::LLVMContext &context, llvm::json::Object *obj, const std::string &input_file) {
  anvill::FunctionDecl decl;

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR) << "Missing function address in specification";
    return false;
  }

  decl.arch = arch;
  decl.address = static_cast<uint64_t>(*maybe_ea);

  if (auto params = obj->getArray("parameters")) {
    for (llvm::json::Value &maybe_param : *params) {
      if (auto param_obj = maybe_param.getAsObject()) {
        auto &pv = decl.params.emplace_back();
        if (!ParseParameter(arch, context, pv, param_obj)) {
          return false;
        }
      } else {
        LOG(ERROR) << "Non-object value in 'parameters' array of "
                   << "function at address '" << std::hex << decl.address
                   << std::dec << "'";
        return false;
      }
    }
  }

  if (auto register_info = obj->getArray("register_info")) {
    for (llvm::json::Value &maybe_reg : *register_info) {
      if (auto reg_obj = maybe_reg.getAsObject()) {

        // decl.register_info.emplace_back();
        // Parse the register info!
        if (!ParseTypedRegister(arch, context, decl.reg_info, reg_obj)) {
          return false;
        }
      } else {
        LOG(ERROR) << "Non-object value in 'register_info' array of "
                   << "function at address '" << decl.address << std::dec
                   << "'";
      }
    }
  }

  // Get the return address location.
  if (auto ret_addr = obj->getObject("return_address")) {
    if (!ParseValue(arch, decl.return_address, ret_addr, "return address")) {
      return false;
    }
  } else {
    LOG(ERROR) << "Non-present or non-object 'return_address' in function "
               << "specification at '" << std::hex << decl.address << std::dec
               << "'";
    return false;
  }

  // Parse the value of the stack pointer on exit from the function, which is
  // defined in terms of `reg + offset` for a value of a register `reg`
  // on entry to the function.
  if (auto ret_sp = obj->getObject("return_stack_pointer")) {
    auto maybe_reg = ret_sp->getString("register");
    if (maybe_reg) {
      decl.return_stack_pointer = arch->RegisterByName(maybe_reg->str());
      if (!decl.return_stack_pointer) {
        LOG(ERROR) << "Unable to locate register '" << maybe_reg->str()
                   << "' used computing the exit value of the "
                   << "stack pointer in function specification at '" << std::hex
                   << decl.address << std::dec << "'";
        return false;
      }
    } else {
      LOG(ERROR)
          << "Non-present or non-string 'register' in 'return_stack_pointer' "
          << "object of function specification at '" << std::hex << decl.address
          << std::dec << "'";
      return false;
    }

    auto maybe_offset = ret_sp->getInteger("offset");
    if (maybe_offset) {
      decl.return_stack_pointer_offset = *maybe_offset;
    }
  } else {
    LOG(ERROR)
        << "Non-present or non-object 'return_stack_pointer' in function "
        << "specification at '" << std::hex << decl.address << std::dec << "'";
    return false;
  }

  if (auto returns = obj->getArray("return_values")) {
    for (llvm::json::Value &maybe_ret : *returns) {
      if (auto ret_obj = maybe_ret.getAsObject()) {
        auto &rv = decl.returns.emplace_back();
        if (!ParseReturnValue(arch, context, rv, ret_obj)) {
          return false;
        }
      } else {
        LOG(ERROR) << "Non-object value in 'return_values' array of "
                   << "function at address '" << std::hex << decl.address
                   << std::dec << "'";
        return false;
      }
    }
  }

  if (auto maybe_is_noreturn = obj->getBoolean("is_noreturn")) {
    decl.is_noreturn = *maybe_is_noreturn;
  }

  if (auto maybe_is_variadic = obj->getBoolean("is_variadic")) {
    decl.is_variadic = *maybe_is_variadic;
  }

  if (auto maybe_cc = obj->getInteger("calling_convention")) {
    decl.calling_convention = static_cast<llvm::CallingConv::ID>(*maybe_cc);
  }

  auto err = DeclareFunction(decl);
  if (remill::IsError(err)) {
    LOG(ERROR) << remill::GetErrorString(err);
    return false;
  }

  return true;
}

bool Program::ParseVariable(const remill::Arch *arch, llvm::LLVMContext &context, llvm::json::Object *obj, const std::string &input_file) {
  anvill::GlobalVarDecl decl;

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR) << "Missing global variable address in specification";
    return false;
  }

  decl.address = static_cast<uint64_t>(*maybe_ea);

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    LOG(ERROR) << "Missing 'type' field in global variable.";
    return false;
  }

  auto maybe_type = llvm_utils::ParseType(context, *maybe_type_str);
  if (remill::IsError(maybe_type)) {
    LOG(ERROR) << remill::GetErrorString(maybe_type);
    return false;
  }

  decl.type = remill::GetReference(maybe_type);
  auto err = DeclareVariable(decl);
  if (remill::IsError(err)) {
    LOG(ERROR) << remill::GetErrorString(err);
    return false;
  }

  return true;
}

bool Program::ParseRange(llvm::json::Object *obj, const std::string &input_file) {
  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR) << "Missing address in memory range specification";
    return false;
  }

  anvill::ByteRange range;
  range.address = static_cast<uint64_t>(*maybe_ea);

  auto perm = obj->getBoolean("is_writeable");
  if (perm) {
    range.is_writeable = *perm;
  }

  perm = obj->getBoolean("is_executable");
  if (perm) {
    range.is_executable = *perm;
  }

  auto maybe_bytes = obj->getString("data");
  if (!maybe_bytes) {
    LOG(ERROR) << "Missing byte string in memory range specification "
               << "at address '" << std::hex << range.address << std::dec
               << '.';
    return false;
  }

  const llvm::StringRef &bytes = *maybe_bytes;
  if (bytes.size() % 2) {
    LOG(ERROR) << "Length of byte string in memory range specification "
               << "at address '" << std::hex << range.address << std::dec
               << "' must have an even number of characters.";
    return false;
  }

  std::vector<uint8_t> decoded_bytes;
  decoded_bytes.reserve(bytes.size() / 2);

  // Parse out the hex-encoded byte sequence.
  for (auto i = 0ul; i < bytes.size(); i += 2) {
    char nibbles[3] = {bytes[i], bytes[i + 1], '\0'};
    char *parsed_to = nullptr;
    auto byte_val = strtol(nibbles, &parsed_to, 16);

    if (parsed_to != &(nibbles[2])) {
      LOG(ERROR) << "Invalid hex byte value '" << nibbles << "' in memory "
                 << "range specification at address '" << std::hex
                 << range.address << std::dec << "'.";
      return false;
    }

    decoded_bytes.push_back(static_cast<uint8_t>(byte_val));
  }

  range.begin = decoded_bytes.data();
  range.end = decoded_bytes.data() + decoded_bytes.size();

  auto err = MapRange(range);
  if (remill::IsError(err)) {
    LOG(ERROR) << remill::GetErrorString(err);
    return false;
  }

  return true;
}

bool Program::ParseControlFlowRedirection(llvm::json::Array &redirection_list, const std::string &input_file) {
  auto index{0U};

  for (const llvm::json::Value &list_entry : redirection_list) {
    auto address_pair = list_entry.getAsArray();
    if (address_pair == nullptr) {
      LOG(ERROR)
          << "Non-JSON list entry in 'control_flow_redirections' array of spec file '"
          << input_file << "'";

      return false;
    }

    const auto &source_address_obj = address_pair->operator[](0);
    auto opt_source_address = source_address_obj.getAsInteger();
    if (!opt_source_address) {
      LOG(ERROR)
          << "Invalid integer value in source address for the #" << index
          << " entry of the control_flow_redirections in the following spec file: '"
          << input_file << "'";

      return false;
    }

    const auto &dest_address_obj = address_pair->operator[](1);
    auto opt_dest_address = dest_address_obj.getAsInteger();
    if (!opt_dest_address) {
      LOG(ERROR)
          << "Invalid integer value in destination address for the #" << index
          << " entry of the control_flow_redirections in the following spec file: '"
          << input_file << "'";

      return false;
    }

    auto source_address = opt_source_address.getValue();
    auto dest_address = opt_dest_address.getValue();
    AddControlFlowRedirection(source_address, dest_address);

    ++index;
  }

  return true;
}

bool Program::ParseParameter(const remill::Arch *arch, llvm::LLVMContext &context,
                           anvill::ParameterDecl &decl,
                           llvm::json::Object *obj) {

  auto maybe_name = obj->getString("name");
  if (maybe_name) {
    decl.name = maybe_name->str();
  } else {
    LOG(WARNING) << "Missing function parameter name.";
  }

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    LOG(ERROR) << "Missing 'type' field in function parameter.";
    return false;
  }

  auto maybe_type = llvm_utils::ParseType(context, *maybe_type_str);
  if (remill::IsError(maybe_type)) {
    LOG(ERROR) << remill::GetErrorString(maybe_type);
    return false;
  }

  decl.type = remill::GetReference(maybe_type);
  return ParseValue(arch, decl, obj, "function parameter");
}

bool Program::ParseValue(const remill::Arch *arch, anvill::ValueDecl &decl, llvm::json::Object *obj, const char *desc) {
  auto maybe_reg = obj->getString("register");
  if (maybe_reg) {
    decl.reg = arch->RegisterByName(maybe_reg->str());
    if (!decl.reg) {
      LOG(ERROR) << "Unable to locate register '" << maybe_reg->str()
                 << "' used for storing " << desc << ".";
      return false;
    }
  }

  if (auto mem_obj = obj->getObject("memory")) {
    maybe_reg = mem_obj->getString("register");
    if (maybe_reg) {
      decl.mem_reg = arch->RegisterByName(maybe_reg->str());
      if (!decl.mem_reg) {
        LOG(ERROR) << "Unable to locate memory base register '"
                   << maybe_reg->str() << "' used for storing " << desc << ".";
        return false;
      }
    }

    auto maybe_offset = mem_obj->getInteger("offset");
    if (maybe_offset) {
      decl.mem_offset = *maybe_offset;
    }
  }

  if (decl.reg && decl.mem_reg) {
    LOG(ERROR) << "A " << desc << " cannot be resident in both a register "
               << "and a memory location.";
    return false;
  } else if (!decl.reg && !decl.mem_reg) {
    LOG(ERROR)
        << "A " << desc << " must be resident in either a register or "
        << "a memory location (defined in terms of a register and offset).";
    return false;
  }

  return true;
}

bool Program::ParseTypedRegister( const remill::Arch *arch, llvm::LLVMContext &context, std::unordered_map<uint64_t, std::vector<anvill::TypedRegisterDecl>> &reg_map, llvm::json::Object *obj) {

  auto maybe_address = obj->getInteger("address");
  if (!maybe_address) {
    LOG(ERROR) << "Missing 'address' field in typed register.";
    return false;
  }
  anvill::TypedRegisterDecl decl;
  auto maybe_value = obj->getInteger("value");
  if (maybe_value) {
    decl.value = *maybe_value;
  }

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    LOG(ERROR) << "Missing 'type' field in typed register.";
    return false;
  }

  auto maybe_type = llvm_utils::ParseType(context, *maybe_type_str);
  if (remill::IsError(maybe_type)) {
    LOG(ERROR) << remill::GetErrorString(maybe_type);
    return false;
  }

  decl.type = remill::GetReference(maybe_type);

  auto register_name = obj->getString("register");
  if (!register_name) {
    LOG(ERROR) << "Missing 'register' field in typed register";
    return false;
  }

  auto maybe_reg = arch->RegisterByName(register_name->str());
  if (!maybe_reg) {
    LOG(ERROR) << "Unable to locate register '" << register_name->str()
               << "' for typed register information:"
               << " at '" << std::hex << *maybe_address << std::dec << "'";
    return false;
  }

  decl.reg = maybe_reg;
  reg_map[*maybe_address].emplace_back(std::move(decl));
  return true;
}

// Parse a return value from the JSON spec.
bool Program::ParseReturnValue(const remill::Arch *arch,
                             llvm::LLVMContext &context,
                             anvill::ValueDecl &decl, llvm::json::Object *obj) {

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    LOG(ERROR) << "Missing 'type' field in function return value.";
    return false;
  }

  auto maybe_type = llvm_utils::ParseType(context, *maybe_type_str);
  if (remill::IsError(maybe_type)) {
    LOG(ERROR) << remill::GetErrorString(maybe_type);
    return false;
  }

  decl.type = remill::GetReference(maybe_type);
  return ParseValue(arch, decl, obj, "function return value");
}

}  //  namespace anvill
