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

#pragma once

#include "ByteSequence.h"
#include "Decl/Decl.h"

#include <remill/BC/Compat/Error.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <filesystem>

namespace anvill {

// Represents a range of bytes, whose data is found in the range
// `[begin, end)`.
struct ByteRange {
  uint64_t address{0};
  const uint8_t *begin{nullptr};
  const uint8_t *end{nullptr};  // Exclusive.
  bool is_writeable{false};
  bool is_executable{false};
};

// A view into a program binary and its data.
//
// NOTE(pag): A variable and a function can be co-located,
//            but two variables cannot share the same address,
//            nor can two functions share the same address.
//
// NOTE(pag): Multiple functions/variables can share the same
//            name. This is common in the core dump / snapshot
//            scenario. For example, an ELF relocatable binary
//            will have a GOT/PLT entry thunk/stub for an external
//            function, and this stub will share the same name
//            as the intended target, which would could be a
//            function defined in a shared library, also present
//            in the address space.
class Program final {
 public:
  using Ptr = std::unique_ptr<Program>;

  static Ptr CreateFromSpecFile(const remill::Arch *arch, llvm::LLVMContext &context, const std::filesystem::path &spec_file_path);
  ~Program(void);

  // Map a range of bytes into the program.
  //
  // This expects that none of the bytes already in that range
  // are mapped. There are no requirements on the alignment
  // of the mapped bytes.
  llvm::Error MapRange(const ByteRange &range);

  // Declare a function in this view. This takes in a function
  // declaration that will act as a sort of "template" for the
  // declaration that we will make and will be owned by `Program`.
  //
  // What is expected of a declaration template:
  //    - `arch` is non-nullptr.
  //    - `address` is unique across all functions, and can be
  //      represented as a 48 bit signed integer.
  //    - `type` is nullptr. This function will create the
  //      appropriate LLVM type given the types in `params` and
  //      `returns`. This implies those values must have correct
  //      LLVM types.
  //    - `name` is optional, and if empty, will be initialized
  //      according to the `sub_xxx` convention.
  //    - All other fields be filled out.
  //
  // This function will check for error conditions and report them
  // as appropriate.
  llvm::Expected<FunctionDecl *>
  DeclareFunction(const FunctionDecl &decl_template, bool force = false);

  // Internal iterator over all functions.
  //
  // NOTE(pag): New functions *can* be declared while this method
  //            is actively iterating.
  void
  ForEachFunction(std::function<bool(const FunctionDecl *)> callback);

  // Search for a specific function by its address.
  FunctionDecl *FindFunction(uint64_t address);

  // Call `callback` on each function with the given name.
  //
  // NOTE(pag): The same function may be revisited if a function
  //            is added within the dynamic scope of `callback`s
  //            execution.
  void ForEachFunctionWithName(
      const std::string &name,
      std::function<bool(const FunctionDecl *)> callback);

  // Returns a possible control flow redirection for the given address
  // or the input address itself if nothing is found
  bool TryGetControlFlowRedirection(std::uint64_t &destination,
                                    std::uint64_t address);

  // Adds a new control flow redirection entry
  void AddControlFlowRedirection(std::uint64_t from, std::uint64_t to);

  // Add a name to an address.
  void AddNameToAddress(const std::string &name, uint64_t address);

  // Apply a function `cb` to each name of the address `address`.
  void ForEachNameOfAddress(
      uint64_t address,
      std::function<bool(const std::string &, const FunctionDecl *,
                         const GlobalVarDecl *)>
          cb);

  // Apply a function `cb` to each address of the named symbol `name`.
  void ForEachAddressOfName(
      const std::string &name,
      std::function<bool(uint64_t, const FunctionDecl *, const GlobalVarDecl *)>
          cb);

  // Apply a function `cb` to each address/name pair.
  void ForEachNamedAddress(
      std::function<bool(uint64_t, const std::string &, const FunctionDecl *,
                         const GlobalVarDecl *)>
          cb);

  // Declare a variable in this view. This takes in a variable
  // declaration that will act as a sort of "template" for the
  // declaration that we will make and will be owned by `Program`.
  //
  // What is expected of a declaration template:
  //    - `arch` is non-nullptr.
  //    - `address` is unique across all variables, and can be
  //      represented as a 48 bit signed integer.
  //    - `type` is non-nullptr.
  //    - `name` is optional, and if empty, will be initialized
  //      according to the `data_xxx` convention.
  //
  // This function will check for error conditions and report them
  // as appropriate.
  llvm::Error DeclareVariable(const GlobalVarDecl &decl_template);

  // Internal iterator over all vars.
  //
  // NOTE(pag): New variables *can* be declared while this method
  //            is actively iterating.
  void
  ForEachVariable(std::function<bool(const GlobalVarDecl *)> callback);

  // Search for a specific variable by its address.
  GlobalVarDecl *FindVariable(uint64_t address);

  // Determine if an address lies somewhere within a known variable
  GlobalVarDecl *FindInVariable(uint64_t address, const llvm::DataLayout &layout);

  // Call `callback` on each variable with the given name.
  //
  // NOTE(pag): The same variable may be revisited if a function
  //            is added within the dynamic scope of `callback`s
  //            execution.
  void ForEachVariableWithName(
      const std::string &name,
      std::function<bool(const GlobalVarDecl *)> callback);

  // Access memory, looking for a specific byte. Returns the byte found, if any.
  Byte FindByte(uint64_t address);

  // Access memory, looking for a specific byte. Returns
  // a reference to the found byte, or to an invalid byte.
  std::pair<Byte::Data *, Byte::Meta *>
  FindByteTuple(uint64_t address);

  // Find which byte sequence (defined in the spec) has the provided `address`
  ByteSequence FindBytesContaining(uint64_t address);

  std::tuple<Byte::Data *, Byte::Meta *, size_t, uint64_t>
  FindBytesContainingTuple(uint64_t address);

  // Find the next byte.
  Byte FindNextByte(Byte byte);

  // Find a sequence of bytes within the same mapped range starting at
  // `address` and including as many bytes fall within the range up to
  // but not including `address+size`.
  ByteSequence FindBytes(uint64_t address, size_t size);

  std::tuple<Byte::Data *, Byte::Meta *, size_t> FindBytesTuple(uint64_t address, size_t size);

private:
  // Mapping between addresses and names.
  std::multimap<uint64_t, std::string> ea_to_name;
  std::multimap<std::string, uint64_t> name_to_ea;

  // Declarations for the functions.
  // TODO: Do not sort this inside ForEach* methods, as it breaks
  // the const qualifier
  bool funcs_are_sorted{true};
  std::vector<std::unique_ptr<FunctionDecl>> funcs;
  std::unordered_map<uint64_t, FunctionDecl *> ea_to_func;

  // Control flow redirections
  std::unordered_map<std::uint64_t, std::uint64_t> ctrl_flow_redirections;

  // Declarations for the variables.
  // TODO: Do not sort this inside ForEach* methods, as it breaks
  // the const qualifier
  bool vars_are_sorted{true};
  std::vector<std::unique_ptr<GlobalVarDecl>> vars;
  std::map<uint64_t, GlobalVarDecl *> ea_to_var;

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

  Program(const remill::Arch *arch, llvm::LLVMContext &context, const std::filesystem::path &spec_file_path);

  bool ParseSpec(const remill::Arch *arch, llvm::LLVMContext &context, llvm::json::Object *spec, const std::string &input_file);

  bool ParseFunction(const remill::Arch *arch, llvm::LLVMContext &context, llvm::json::Object *obj, const std::string &input_file);

  bool ParseVariable(const remill::Arch *arch, llvm::LLVMContext &context, llvm::json::Object *obj, const std::string &input_file);

  bool ParseRange(llvm::json::Object *obj, const std::string &input_file);

  bool ParseControlFlowRedirection(llvm::json::Array &redirection_list, const std::string &input_file);

  bool ParseParameter(const remill::Arch *arch, llvm::LLVMContext &context, anvill::ParameterDecl &decl, llvm::json::Object *obj);

  bool ParseValue(const remill::Arch *arch, anvill::ValueDecl &decl, llvm::json::Object *obj, const char *desc);

  bool ParseTypedRegister( const remill::Arch *arch, llvm::LLVMContext &context, std::unordered_map<uint64_t, std::vector<anvill::TypedRegisterDecl>> &reg_map, llvm::json::Object *obj);

  bool ParseReturnValue(const remill::Arch *arch,
                              llvm::LLVMContext &context,
                              anvill::ValueDecl &decl, llvm::json::Object *obj);
};

}  // namespace anvill
