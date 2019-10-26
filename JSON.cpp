/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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

#include <cstdint>
#include <ios>
#include <memory>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/Compat/Error.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include "anvill/Analyze.h"
#include "anvill/Decl.h"
#include "anvill/Optimize.h"
#include "anvill/Lift.h"
#include "anvill/Program.h"
#include "anvill/TypeParser.h"

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_string(spec, "", "Path to a JSON specification of code to decompile.");
DEFINE_string(ir_out, "", "Path to file where the LLVM IR should be saved.");
DEFINE_string(bc_out, "", "Path to file where the LLVM bitcode should be "
                          "saved.");

namespace {

// Parse the location of a value. This applies to both parameters and
// return values.
static bool ParseValue(
    const remill::Arch *arch,
    anvill::ValueDecl &decl,
    llvm::json::Object *obj,
    const char *desc) {

  auto maybe_reg = obj->getString("register");
  if (maybe_reg) {
    decl.reg = arch->RegisterByName(maybe_reg->str());
    if (!decl.reg) {
      LOG(ERROR)
          << "Unable to locate register '" << maybe_reg->str()
          << "' used for storing " << desc << ".";
      return false;
    }
  }

  if (auto mem_obj = obj->getObject("memory")) {
    maybe_reg = mem_obj->getString("register");
    if (maybe_reg) {
      decl.mem_reg = arch->RegisterByName(maybe_reg->str());
      if (!decl.mem_reg) {
        LOG(ERROR)
            << "Unable to locate memory base register '"
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
    LOG(ERROR)
        << "A " << desc << " cannot be resident in both a register "
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

// Parse a parameter from the JSON spec. Parameters should have names,
// as that makes the bitcode slightly easier to read, but names are
// not required. They must have types, and these types should be mostly
// reflective of what you would see if you compiled C/C++ source code to
// LLVM bitcode, and inspected the type of the corresponding parameter in
// the bitcode.
static bool ParseParameter(
    const remill::Arch *arch,
    llvm::LLVMContext &context,
    anvill::ParameterDecl &decl,
    llvm::json::Object *obj) {

  auto maybe_name = obj->getString("name");
  if (maybe_name) {
    decl.name = maybe_name->str();
  } else {
    LOG(WARNING)
        << "Missing function parameter name.";
  }

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    LOG(ERROR)
        << "Missing 'type' field in function parameter.";
    return false;
  }

  auto maybe_type = anvill::ParseType(context, *maybe_type_str);
  if (remill::IsError(maybe_type)) {
    LOG(ERROR)
        << remill::GetErrorString(maybe_type);
    return false;
  }

  decl.type = remill::GetReference(maybe_type);
  return ParseValue(arch, decl, obj, "function parameter");
}

// Parse a return value from the JSON spec.
static bool ParseReturnValue(
    const remill::Arch *arch,
    llvm::LLVMContext &context,
    anvill::ValueDecl &decl,
    llvm::json::Object *obj) {

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    LOG(ERROR)
        << "Missing 'type' field in function return value.";
    return false;
  }

  auto maybe_type = anvill::ParseType(context, *maybe_type_str);
  if (remill::IsError(maybe_type)) {
    LOG(ERROR)
        << remill::GetErrorString(maybe_type);
    return false;
  }

  decl.type = remill::GetReference(maybe_type);
  return ParseValue(arch, decl, obj, "function return value");
}

// Try to unserialize function info from a JSON specification. These
// are really function prototypes / declarations, and not any isntruction
// data (that is separate, if present).
static bool ParseFunction(
    const remill::Arch *arch,
    llvm::LLVMContext &context,
    anvill::Program &program,
    llvm::json::Object *obj) {

  anvill::FunctionDecl decl;

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR)
        << "Missing function address in specification";
    return false;
  }

  decl.arch = arch;
  decl.address = static_cast<uint64_t>(*maybe_ea);

  auto maybe_name = obj->getString("name");
  if (maybe_name) {
    decl.name = maybe_name->str();
  }

  if (auto params = obj->getArray("parameters")) {
    for (llvm::json::Value &maybe_param : *params) {
      if (auto param_obj = maybe_param.getAsObject()) {
        decl.params.emplace_back();
        if (!ParseParameter(arch, context, decl.params.back(), param_obj)) {
          return false;
        }
      } else {
        LOG(ERROR)
            << "Non-object value in 'parameters' array of "
            << "function at address '" << std::hex
            << decl.address << std::dec << "'";
        return false;
      }
    }
  }

  // Get the return address location.
  if (auto ret_addr = obj->getObject("return_address")) {
    if (!ParseValue(arch, decl.return_address, ret_addr, "return address")) {
      return false;
    }
  } else {
    LOG(ERROR)
        << "Non-present or non-object 'return_address' in function "
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
        LOG(ERROR)
            << "Unable to locate register '" << maybe_reg->str()
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
        << "specification at '" << std::hex << decl.address << std::dec
        << "'";
    return false;
  }

  if (auto returns = obj->getArray("return_values")) {
    for (llvm::json::Value &maybe_ret : *returns) {
      if (auto ret_obj = maybe_ret.getAsObject()) {
        decl.returns.emplace_back();
        if (!ParseReturnValue(arch, context, decl.returns.back(), ret_obj)) {
          return false;
        }
      } else {
        LOG(ERROR)
            << "Non-object value in 'return_values' array of "
            << "function at address '" << std::hex
            << decl.address << std::dec << "'";
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

  auto err = program.DeclareFunction(decl);
  if (remill::IsError(err)) {
    LOG(ERROR)
        << remill::GetErrorString(err);
    return false;
  }

  return true;
}

// Try to unserialize variable information.
static bool ParseVariable(const remill::Arch *arch,
                          llvm::LLVMContext &context,
                          anvill::Program &program,
                          llvm::json::Object *obj) {
  anvill::GlobalVarDecl decl;

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR)
        << "Missing global variable address in specification";
    return false;
  }

  decl.address = static_cast<uint64_t>(*maybe_ea);

  auto maybe_name = obj->getString("name");
  if (maybe_name) {
    decl.name = maybe_name->str();
  }

  auto maybe_type_str = obj->getString("type");
  if (!maybe_type_str) {
    LOG(ERROR)
        << "Missing 'type' field in global variable.";
    return false;
  }

  auto maybe_type = anvill::ParseType(context, *maybe_type_str);
  if (remill::IsError(maybe_type)) {
    LOG(ERROR)
        << remill::GetErrorString(maybe_type);
  }

  decl.type = remill::GetReference(maybe_type);
  auto err = program.DeclareVariable(decl);
  if (remill::IsError(err)) {
    LOG(ERROR)
        << remill::GetErrorString(err);
    return false;
  }

  return true;
}

// Parse a memory range.
static bool ParseRange(anvill::Program &program,
                       llvm::json::Object *obj) {

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR)
        << "Missing address in memory range specification";
    return false;
  }

  anvill::ByteRange range;
  range.address = static_cast<uint64_t>(*maybe_ea);

  auto perm = obj->getBoolean("is_readable");
  if (perm) {
    range.is_readable = *perm;
  }

  perm = obj->getBoolean("is_writeable");
  if (perm) {
    range.is_writeable = *perm;
  }

  perm = obj->getBoolean("is_executable");
  if (perm) {
    range.is_executable = *perm;
  }

  auto maybe_bytes = obj->getString("data");
  if (!maybe_bytes) {
    LOG(ERROR)
        << "Missing byte string in memory range specification "
        << "at address '" << std::hex << range.address
        << std::dec << '.';
    return false;
  }

  const llvm::StringRef &bytes = *maybe_bytes;
  if (bytes.size() % 2) {
    LOG(ERROR)
        << "Length of byte string in memory range specification "
        << "at address '" << std::hex << range.address
        << std::dec << "' must have an even number of characters.";
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
      LOG(ERROR)
          << "Invalid hex byte value '" << nibbles << "' in memory "
          << "range specification at address '" << std::hex
          << range.address << std::dec << "'.";
      return false;
    }

    decoded_bytes.push_back(static_cast<uint8_t>(byte_val));
  }

  range.begin = decoded_bytes.data();
  range.end = decoded_bytes.data() + decoded_bytes.size();

  auto err = program.MapRange(range);
  if (remill::IsError(err)) {
    LOG(ERROR)
        << remill::GetErrorString(err);
    return false;
  }

  return true;
}


// Parse a stack declaration. This is a concrete range of memory that
// is not itself part of any ranges, and will be used to "fake" the
// stack frames of the functions.
static bool ParseStack(
    anvill::Program &program,
    llvm::json::Object *obj) {

  auto maybe_ea = obj->getInteger("address");
  if (!maybe_ea) {
    LOG(ERROR)
        << "Missing 'address' in stack specification";
    return false;
  }

  auto maybe_size = obj->getInteger("size");
  if (!maybe_size) {
    LOG(ERROR)
        << "Missing 'size' in stack specification";
    return false;
  }

  auto maybe_start_offset = obj->getInteger("start_offset");
  if (!maybe_start_offset) {
    LOG(ERROR)
        << "Missing 'start_offset' in stack specification";
    return false;
  }

  auto size = *maybe_size;
  if (0 >= size) {
    LOG(ERROR)
        << "Zero- or negative-valued 'size' in stack specification";
    return false;
  }

  auto start_offset = *maybe_start_offset;
  if (0 > start_offset) {
    LOG(ERROR)
        << "Negative 'start_offset' in stack specification";
    return false;
  }

  std::vector<uint8_t> data;
  data.resize(static_cast<size_t>(size));

  auto address = static_cast<uint64_t>(*maybe_ea);
  auto err = program.MapStack(
      address, address + static_cast<uint64_t>(size),
      address + static_cast<uint64_t>(start_offset));

  if (remill::IsError(err)) {
    LOG(ERROR)
        << remill::GetErrorString(err);
    return false;
  }

  return true;
}

// Parse the core data out of a JSON specification, and do a small
// amount of validation. A JSON spec contains the following:
//
//  - For each function:
//    - Function name (if any)
//    - Address.
//    - For each argument:
//    - - Argument name
//    - - Location specifier, which is a register name or a stack pointer displacement.
//    - - Type.
//    - For each return value
//    - - Location specifier
//    - - Type.
//
//  - For each global variable:
//    - Variable name (if any)
//    - Type.
//    - Address.
//
//  - For each memory range:
//    - Starting address. No alignment restrictions apply.
//    - Permissions (is_readable, is_writeable, is_executable).
//    - Data (hex-encoded byte string).
static bool ParseSpec(
    const remill::Arch *arch,
    llvm::LLVMContext &context,
    anvill::Program &program,
    llvm::json::Object *spec) {

  auto num_funcs = 0;
  if (auto funcs = spec->getArray("functions")) {
    for (llvm::json::Value &func : *funcs) {
      if (auto func_obj = func.getAsObject()) {
        if (!ParseFunction(arch, context, program, func_obj)) {
          return false;
        } else {
          ++num_funcs;
        }
      } else {
        LOG(ERROR)
            << "Non-JSON object in 'functions' array of spec file '"
            << FLAGS_spec << "'";
        return false;
      }
    }
  } else if (spec->find("functions") != spec->end()) {
    LOG(ERROR)
        << "Non-JSON array value for 'functions' in spec file '"
        << FLAGS_spec << "'";
    return false;
  }

  if (auto vars = spec->getArray("variables")) {
    for (llvm::json::Value &var : *vars) {
      if (auto var_obj = var.getAsObject()) {
        if (!ParseVariable(arch, context, program, var_obj)) {
          return false;
        }
      } else {
        LOG(ERROR)
            << "Non-JSON object in 'variables' array of spec file '"
            << FLAGS_spec << "'";
        return false;
      }
    }
  } else if (spec->find("variables") != spec->end()) {
    LOG(ERROR)
        << "Non-JSON array value for 'variables' in spec file '"
        << FLAGS_spec << "'";
    return false;
  }

  if (auto ranges = spec->getArray("memory")) {
    for (llvm::json::Value &range : *ranges) {
      if (auto range_obj = range.getAsObject()) {
        if (!ParseRange(program, range_obj)) {
          return false;
        }
      } else {
        LOG(ERROR)
            << "Non-JSON object in 'bytes' array of spec file '"
            << FLAGS_spec << "'";
        return false;
      }
    }
  } else if (spec->find("memory") != spec->end()) {
    LOG(ERROR)
        << "Non-JSON array value for 'memory' in spec file '"
        << FLAGS_spec << "'";
    return false;
  }

  if (auto stack = spec->getObject("stack")) {
    if (!ParseStack(program, stack)) {
      return false;
    }
  } else {
    LOG(ERROR)
        << "Absent or non-object value in 'stack' field of spec file '"
        << FLAGS_spec << "'";
    return false;
  }

  return true;
}

}  // namespace

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);

  if (FLAGS_spec.empty()) {
    LOG(ERROR)
        << "Please specify a path to a JSON specification file in --spec.";
    return EXIT_FAILURE;
  }

  if (FLAGS_spec == "/dev/stdin") {
    FLAGS_spec = "-";
  }

  auto maybe_buff = llvm::MemoryBuffer::getFileOrSTDIN(FLAGS_spec);
  if (remill::IsError(maybe_buff)) {
    LOG(ERROR)
        << "Unable to read JSON spec file '" << FLAGS_spec << "': "
        << remill::GetErrorString(maybe_buff);
    return EXIT_FAILURE;
  }

  const auto &buff = remill::GetReference(maybe_buff);
  auto maybe_json = llvm::json::parse(buff->getBuffer());
  if (remill::IsError(maybe_json)) {
    LOG(ERROR)
        << "Unable to parse JSON spec file '" << FLAGS_spec << "': "
        << remill::GetErrorString(maybe_json);
    return EXIT_FAILURE;
  }

  auto &json = remill::GetReference(maybe_json);
  const auto spec = json.getAsObject();
  if (!spec) {
    LOG(ERROR)
        << "JSON spec file '" << FLAGS_spec << "' must contain a single object.";
    return EXIT_FAILURE;
  }

  // Take the architecture and OS names out of the JSON spec, and
  // fall back on the command-line flags if those are missing.
  auto maybe_arch = spec->getString("arch");
  auto arch_str = FLAGS_arch;
  if (maybe_arch) {
    arch_str = maybe_arch->str();
  }

  auto maybe_os = spec->getString("os");
  auto os_str = FLAGS_os;
  if (maybe_os) {
    os_str = maybe_os->str();
  }

  const auto arch_name = remill::GetArchName(arch_str);
  const auto os_name = remill::GetOSName(os_str);

  llvm::LLVMContext context;
  auto arch = remill::Arch::Get(context, os_name, arch_name);
  if (!arch) {
    return EXIT_FAILURE;
  }

  // NOTE(pag): This needs to come first, unfortunately, as the
  //            only way for `arch` to learn about the organization
  //            of the state structure and its named registers is
  //            by analyzing a module, and this is done in `PrepareModule`,
  //            which is called by `LoadArchSemantics`.
  std::unique_ptr<llvm::Module> semantics(remill::LoadArchSemantics(arch));
  remill::IntrinsicTable intrinsics(semantics);

  anvill::Program program;
  if (!ParseSpec(arch, context, program, spec)) {
    return EXIT_FAILURE;
  }

  std::unordered_map<uint64_t, llvm::GlobalVariable *> global_vars;
  std::unordered_map<uint64_t, llvm::Function *> lift_targets;

  program.ForEachVariable([&] (const anvill::GlobalVarDecl *decl) {
    global_vars[decl->address] = decl->DeclareInModule(*semantics);
    return true;
  });

  auto trace_manager = anvill::TraceManager::Create(
      *semantics, program);

  remill::InstructionLifter inst_lifter(arch, intrinsics);
  remill::TraceLifter trace_lifter(inst_lifter, *trace_manager);

  program.ForEachFunction([&] (const anvill::FunctionDecl *decl) {
    auto byte = program.FindByte(decl->address);
    if (byte.IsExecutable() && !byte.IsWriteable()) {
      trace_lifter.Lift(byte.Address());
    }
    return true;
  });

  // Optimize the module, but with a particular focus on only the functions
  // that we actually lifted.
  anvill::OptimizeModule(program, *semantics);

  llvm::Module dest_module("", context);
  arch->PrepareModuleDataLayout(&dest_module);

  program.ForEachFunction([&] (const anvill::FunctionDecl *decl) {
    const auto func = decl->DeclareInModule(*semantics);
    remill::MoveFunctionIntoModule(func, &dest_module);
    return true;
  });

  anvill::OptimizeModule(program, dest_module);
  anvill::RecoveryMemoryAccesses(program, dest_module);
  anvill::OptimizeModule(program, dest_module);

  int ret = EXIT_SUCCESS;

  if (!FLAGS_ir_out.empty()) {
    if (!remill::StoreModuleIRToFile(&dest_module, FLAGS_ir_out, true)) {
      LOG(ERROR)
          << "Could not save LLVM IR to " << FLAGS_ir_out;
      ret = EXIT_FAILURE;
    }
  }
  if (!FLAGS_bc_out.empty()) {
    if (!remill::StoreModuleToFile(&dest_module, FLAGS_bc_out, true)) {
      LOG(ERROR)
          << "Could not save LLVM bitcode to " << FLAGS_bc_out;
      ret = EXIT_FAILURE;
    }
  }

  return ret;
}
