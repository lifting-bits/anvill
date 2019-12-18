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

#include "anvill/Lift.h"

#include <glog/logging.h>

#include <unordered_map>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include "Lift.h"

#include "anvill/Decl.h"
#include "anvill/Program.h"

namespace anvill {

// Produce one or more instructions in `in_block` to load and return
// the lifted value associated with `decl`.
llvm::Value *LoadLiftedValue(
    const ValueDecl &decl,
    const remill::IntrinsicTable &intrinsics,
    llvm::BasicBlock *in_block,
    llvm::Value *state_ptr,
    llvm::Value *mem_ptr) {

  auto func = in_block->getParent();
  auto module = func->getParent();

  CHECK_EQ(module, intrinsics.read_memory_8->getParent());

  // Load it out of a register.
  if (decl.reg) {
    auto ptr_to_reg = decl.reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    return ir.CreateLoad(ir.CreateBitCast(
        ptr_to_reg,
        llvm::PointerType::get(decl.type, 0)));

    // Load it out of memory.
  } else if (decl.mem_reg) {
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    const auto addr = ir.CreateAdd(
        ir.CreateLoad(ptr_to_reg),
        llvm::ConstantInt::get(
            decl.mem_reg->type, static_cast<uint64_t>(decl.mem_offset), true));
    return llvm::dyn_cast<llvm::Instruction>(remill::LoadFromMemory(
        intrinsics, in_block, decl.type, mem_ptr, addr));

  } else {
    return llvm::UndefValue::get(decl.type);
  }
}

// Produce one or more instructions in `in_block` to store the
// native value `native_val` into the lifted state associated
// with `decl`.
llvm::Value *StoreNativeValue(
    llvm::Value *native_val,
    const ValueDecl &decl,
    const remill::IntrinsicTable &intrinsics,
    llvm::BasicBlock *in_block,
    llvm::Value *state_ptr,
    llvm::Value *mem_ptr) {

  auto func = in_block->getParent();
  auto module = func->getParent();

  CHECK_EQ(module, intrinsics.read_memory_8->getParent());
  CHECK_EQ(native_val->getType(), decl.type);

  // Store it to a register.
  if (decl.reg) {
    auto ptr_to_reg = decl.reg->AddressOf(state_ptr, in_block);
    llvm::IRBuilder<> ir(in_block);
    ir.CreateStore(
        native_val,
        ir.CreateBitCast(
            ptr_to_reg, llvm::PointerType::get(decl.type, 0)));
    return mem_ptr;

    // Store it to memory.
  } else if (decl.mem_reg) {
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, in_block);

    llvm::IRBuilder<> ir(in_block);
    const auto addr = ir.CreateAdd(
        ir.CreateLoad(ptr_to_reg),
        llvm::ConstantInt::get(
            decl.mem_reg->type, static_cast<uint64_t>(decl.mem_offset), true));
    return remill::StoreToMemory(
        intrinsics, in_block, native_val, mem_ptr, addr);

  } else {
    return llvm::UndefValue::get(mem_ptr->getType());
  }
}

namespace {

// Create an adaptor function that converts lifted state to native state.
// This function is marked as always-inline so that when a lifted function
// calls this function, it ends up doing so in a way that, post-optimization,
// ends up calling the higher-level function.
static llvm::Function *CreateLiftedToNativeStateFunction(
    const remill::IntrinsicTable &intrinsics,
    const anvill::FunctionDecl *decl) {

  auto module = intrinsics.error->getParent();
  auto adaptor = remill::DeclareLiftedFunction(
      module, decl->name + ".anvill.lifted_to_native");

  // Declare all registers in that function. Makes life easier.
  remill::CloneBlockFunctionInto(adaptor);

  auto block = &(adaptor->getEntryBlock());
  auto state_ptr = remill::LoadStatePointer(block);
  auto mem_ptr = remill::LoadMemoryPointer(block);
  auto new_mem_ptr = decl->CallFromLiftedBlock(
      intrinsics, block, state_ptr, mem_ptr);

  llvm::IRBuilder<> ir(block);
  ir.CreateRet(new_mem_ptr);

  adaptor->addFnAttr(llvm::Attribute::InlineHint);
  adaptor->addFnAttr(llvm::Attribute::AlwaysInline);
  adaptor->setLinkage(llvm::GlobalValue::PrivateLinkage);

  return adaptor;
}

// Manager of lifted traces. This interacts with Remill's
// `TraceLifter` class, which performs a recursive-descent
// decoding of instructions.
class TraceManagerImpl final : public TraceManager {
 public:
  virtual ~TraceManagerImpl(void) = default;

  TraceManagerImpl(
      llvm::Module &semantics_module,
      const Program &program_)
      : intrinsics(&semantics_module),
        program(program_) {
    auto sp = program.InitialStackPointer();
    if (!sp) {
      LOG(FATAL) << "Found invalid initial stack pointer";
    }
    initial_stack_pointer = *sp;
  }

  // Use something that won't conflict with our default naming of
  // unnamed `FunctionDecl`s so that we avoid some declaration vs.
  // definition conflicts in Remill's TraceLifter.
  std::string TraceName(uint64_t addr) final {
    std::stringstream ss;
    ss << "sub_" << std::hex << addr << ".anvill.lifted";
    return ss.str();
  }

  // Called when we have lifted, i.e. defined the contents, of a new trace.
  // The derived class is expected to do something useful with this.
  void SetLiftedTraceDefinition(
      uint64_t addr, llvm::Function *lifted_func) final;

  // Get a declaration for a lifted trace.
  llvm::Function *GetLiftedTraceDeclaration(uint64_t addr) final {
    auto trace_it = trace_decls.find(addr);
    if (trace_it != trace_decls.end()) {
      return trace_it->second;
    }

    auto decl = program.FindFunction(addr);
    if (!decl) {
      return nullptr;
    }

    const auto trace = CreateLiftedToNativeStateFunction(
        intrinsics, decl);
    trace_decls[addr] = trace;
    return trace;
  }

  // Get a definition for a lifted trace.
  llvm::Function *GetLiftedTraceDefinition(uint64_t addr) final {
    auto trace_it = trace_defs.find(addr);
    if (trace_it != trace_defs.end()) {
      return trace_it->second;
    }

    auto decl = program.FindFunction(addr);
    if (!decl) {
      return nullptr;
    }

    auto byte = program.FindByte(addr);
    if (byte) {
      return nullptr;
    }

    // We don't have the code for this function mapped in, so we
    // want to make sure we never try to lift it.
    return decl->DeclareInModule(*(intrinsics.error->getParent()));
  }

  // Try to read an executable byte of memory. Returns `true` of the byte
  // at address `addr` is executable and readable, and updates the byte
  // pointed to by `byte` with the read value.
  bool TryReadExecutableByte(uint64_t addr, uint8_t *byte) final;

 private:
  TraceManagerImpl(void) = delete;

  const remill::IntrinsicTable intrinsics;
  const Program &program;

  // Trace declarations are our lifted-to-native entrypoints.
  std::unordered_map<uint64_t, llvm::Function *> trace_decls;
  std::unordered_map<uint64_t, llvm::Function *> trace_defs;

  // Our native-to-lifted representations.
  std::unordered_map<uint64_t, llvm::Function *> decompiled_funcs;

  // Initial stack pointer value.
  uint64_t initial_stack_pointer;
};

// Try to read an executable byte of memory. Returns `true` of the byte
// at address `addr` is executable, and updates the byte pointed to by
// `byte` with the read value.
bool TraceManagerImpl::TryReadExecutableByte(uint64_t addr, uint8_t *byte) {
  if (auto addr_byte = program.FindByte(addr)) {
    if (addr_byte.IsExecutable()) {
      auto val = addr_byte.Value();
      if (!val) {
        LOG(FATAL) << "Found invalid address of executable byte";
      }
      *byte = *val;
      return true;
    }
  }
  return false;
}

// Called when we have lifted, i.e. defined the contents, of a new trace.
// The derived class is expected to do something useful with this.
void TraceManagerImpl::SetLiftedTraceDefinition(
    uint64_t addr, llvm::Function *lifted_func) {

  lifted_func->removeFnAttr(llvm::Attribute::NoInline);
  lifted_func->addFnAttr(llvm::Attribute::InlineHint);
  lifted_func->addFnAttr(llvm::Attribute::AlwaysInline);

  // Keep track of all defined traces.
  trace_defs[addr] = lifted_func;

  const auto decl = program.FindFunction(addr);

  // If this isn't a high-level function that we know about,
  // then add it to the set of trace declarations.
  if (!decl) {
    LOG(ERROR)
        << "Missing FunctionDecl for " << std::hex << addr << std::dec;
    trace_decls[addr] = lifted_func;
    lifted_func->setLinkage(llvm::GlobalValue::LinkOnceAnyLinkage);
    return;
  }

  auto module = lifted_func->getParent();
  auto &context = module->getContext();
  const auto func = decl->DeclareInModule(*module);

  decompiled_funcs[addr] = func;

  if (!func->isDeclaration()) {
    LOG(ERROR)
        << "Function associated with FunctionDecl at "
        << std::hex << addr << std::dec << " already defined";
    return;
  }

  const auto arch = decl->arch;
  CHECK_EQ(arch->context, &context);

  // We have the decompiled function, or at least, a prefix of it,
  // so we'll invent a state structure and a stack frame and we'll
  // call the lifted function with that. The lifted function will
  // get inlined into this function.

  auto block = llvm::BasicBlock::Create(context, "", func);
  llvm::IRBuilder<> ir(block);

  // Invent a memory pointer.
  const auto mem_ptr_type = remill::MemoryPointerType(module);
  llvm::Value *mem_ptr = llvm::Constant::getNullValue(mem_ptr_type);

  // Stack-allocate a state pointer.
  const auto state_ptr_type = remill::StatePointerType(module);
  const auto state_type = state_ptr_type->getElementType();
  const auto state_ptr = ir.CreateAlloca(state_type);
  ir.CreateStore(llvm::ConstantAggregateZero::get(state_type), state_ptr);

  // Store the program counter into the state.
  const auto pc_reg = arch->RegisterByName(
      arch->ProgramCounterRegisterName());
  const auto pc_reg_ptr = pc_reg->AddressOf(state_ptr, block);
  const auto pc = llvm::ConstantInt::get(
      pc_reg->type, decl->address, false);
  ir.SetInsertPoint(block);
  ir.CreateStore(pc, pc_reg_ptr);

  // Initialize the stack pointer.
  const auto sp_reg = arch->RegisterByName(
      arch->StackPointerRegisterName());
  const auto sp_reg_ptr = sp_reg->AddressOf(state_ptr, block);
  const auto sp = llvm::ConstantInt::get(
      sp_reg->type, initial_stack_pointer, false);
  ir.SetInsertPoint(block);
  ir.CreateStore(sp, sp_reg_ptr);

  // Put the function's return address wherever it needs to go.
  llvm::Value *ret_addr = ir.CreateCall(
      llvm::Intrinsic::getDeclaration(
          module, llvm::Intrinsic::returnaddress),
  ir.getInt32(0));

  if (ret_addr->getType() != decl->return_address.type) {
    if (decl->return_address.type->isIntegerTy()) {
      ret_addr = ir.CreatePtrToInt(ret_addr, decl->return_address.type);
    } else if (decl->return_address.type->isPointerTy()) {
      ret_addr = ir.CreateBitCast(ret_addr, decl->return_address.type);
    } else {
      LOG(FATAL)
          << "Unexpected type for return address: "
          << remill::LLVMThingToString(decl->return_address.type);
    }
  }

  mem_ptr = StoreNativeValue(
      ret_addr, decl->return_address, intrinsics,
      block, state_ptr, mem_ptr);

  // Store the function parameters either into the state struct
  // or into memory (likely the stack).
  auto arg_index = 0u;
  for (auto &arg : func->args()) {
    auto param_decl = decl->params[arg_index++];
    mem_ptr = StoreNativeValue(
        &arg, param_decl, intrinsics,
        block, state_ptr, mem_ptr);
  }

  llvm::Value *lifted_func_args[remill::kNumBlockArgs] = {};
  lifted_func_args[remill::kStatePointerArgNum] = state_ptr;
  lifted_func_args[remill::kMemoryPointerArgNum] = mem_ptr;
  lifted_func_args[remill::kPCArgNum] = pc;
  mem_ptr = ir.CreateCall(lifted_func, lifted_func_args);

  llvm::Value *ret_val = nullptr;

  if (decl->returns.size() == 1) {
    ret_val = LoadLiftedValue(
        decl->returns.front(), intrinsics, block,
        state_ptr, mem_ptr);
    ir.SetInsertPoint(block);

  } else if (1 < decl->returns.size()){
    ret_val = llvm::UndefValue::get(func->getReturnType());
    auto index = 0u;
    for (auto &ret_decl : decl->returns) {
      auto partial_ret_val = LoadLiftedValue(
          ret_decl, intrinsics, block,
          state_ptr, mem_ptr);
      ir.SetInsertPoint(block);
      unsigned indexes[] = {index};
      ret_val = ir.CreateInsertValue(
          ret_val, partial_ret_val, indexes);
      index += 1;
    }
  }

  if (ret_val) {
    ir.CreateRet(ret_val);
  } else {
    ir.CreateRetVoid();
  }
}

}  // namespace

TraceManager::~TraceManager(void) {}

std::unique_ptr<TraceManager> TraceManager::Create(
    llvm::Module &semantics_module,
    const anvill::Program &program) {
  return std::unique_ptr<TraceManager>(
      new TraceManagerImpl(semantics_module, program));
}

}  // namespace anvill
