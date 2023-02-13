/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "FunctionLifter.h"

#include <anvill/ABI.h>
#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/map_type_handler.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/AutoUpgrade.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Pass.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Context.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Error.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>
#include <remill/OS/OS.h>

#include <algorithm>
#include <array>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include "BasicBlockLifter.h"
#include "EntityLifter.h"
#include "anvill/Declarations.h"
#include "anvill/Specification.h"

namespace anvill {
namespace {


// A function that ensures that the memory pointer escapes, and thus none of
// the memory writes at the end of a function are lost.
static llvm::Function *
GetMemoryEscapeFunc(const remill::IntrinsicTable &intrinsics) {
  const auto module = intrinsics.error->getParent();
  auto &context = module->getContext();

  if (auto func = module->getFunction(kMemoryPointerEscapeFunction)) {
    return func;
  }

  llvm::Type *params[] = {
      remill::NthArgument(intrinsics.error, remill::kMemoryPointerArgNum)
          ->getType()};
  auto type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), params, false);
  return llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage,
                                kMemoryPointerEscapeFunction.data(), module);
}

// Annotate and instruction with the `id` annotation if that instruction
// is unannotated.
static void AnnotateInstruction(llvm::Instruction *inst, unsigned id,
                                llvm::MDNode *annot) {
  if (annot && !inst->getMetadata(id)) {
    inst->setMetadata(id, annot);
  }
}


// Annotate and instruction with the `id` annotation if that instruction
// is unannotated.
static void AnnotateInstructions(llvm::BasicBlock *block, unsigned id,
                                 llvm::MDNode *annot) {
  if (annot) {
    for (auto &inst : *block) {
      AnnotateInstruction(&inst, id, annot);
    }
  }
}

}  // namespace

FunctionLifter::~FunctionLifter(void) {}


FunctionLifter
FunctionLifter::CreateFunctionLifter(const LifterOptions &options_) {
  return FunctionLifter(options_, remill::LoadArchSemantics(options_.arch));
}


FunctionLifter::FunctionLifter(const LifterOptions &options_,
                               std::unique_ptr<llvm::Module> semantics_module)
    : CodeLifter(options_, semantics_module.get(), this->type_specifier),
      semantics_module(std::move(semantics_module)),
      type_specifier(options_.TypeDictionary(), options_.arch) {


  anvill::CloneIntrinsicsFromModule(*this->semantics_module,
                                    *this->options.module);
}


llvm::BranchInst *
FunctionLifter::BranchToInst(uint64_t from_addr, uint64_t to_addr,
                             const remill::DecodingContext &mapper,
                             llvm::BasicBlock *from_block) {
  auto br = llvm::BranchInst::Create(GetOrCreateBlock(to_addr), from_block);
  AnnotateInstruction(br, pc_annotation_id, pc_annotation);
  return br;
}


llvm::BasicBlock *FunctionLifter::GetOrCreateBlock(uint64_t baddr) {
  auto &block = this->addr_to_block[baddr];
  if (block) {
    return block;
  }

  std::stringstream ss;
  ss << "inst_" << std::hex << baddr;
  block = llvm::BasicBlock::Create(llvm_context, ss.str(), lifted_func);

  return block;
}

llvm::BasicBlock *
FunctionLifter::GetOrCreateTargetBlock(const remill::Instruction &from_inst,
                                       uint64_t to_addr,
                                       const remill::DecodingContext &mapper) {
  return GetOrCreateBlock(to_addr);
}


void FunctionLifter::InsertError(llvm::BasicBlock *block) {
  llvm::IRBuilder<> ir{block};
  auto tail = remill::AddTerminatingTailCall(
      ir.GetInsertBlock(), intrinsics.error, this->intrinsics);
  AnnotateInstruction(tail, pc_annotation_id, pc_annotation);
  AnnotateInstruction(tail, pc_annotation_id, pc_annotation);
}


std::optional<CallableDecl>
FunctionLifter::TryGetTargetFunctionType(const remill::Instruction &from_inst,
                                         std::uint64_t address) {
  std::optional<CallableDecl> opt_callable_decl =
      type_provider.TryGetCalledFunctionTypeOrDefault(func_address, from_inst,
                                                      address);

  return opt_callable_decl;
}


// Get the annotation for the program counter `pc`, or `nullptr` if we're
// not doing annotations.
llvm::MDNode *FunctionLifter::GetPCAnnotation(uint64_t pc) const {
  if (options.pc_metadata_name) {
    auto pc_val = llvm::ConstantInt::get(address_type, pc);
    auto pc_md = llvm::ValueAsMetadata::get(pc_val);
    return llvm::MDNode::get(llvm_context, pc_md);
  } else {
    return nullptr;
  }
}


// Declare the function decl `decl` and return an `llvm::Function *`.
llvm::Function *FunctionLifter::GetOrDeclareFunction(const FunctionDecl &decl) {
  const auto func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, llvm_context));

  // NOTE(pag): This may find declarations from prior lifts that have been
  //            left around in the semantics module.
  auto &native_func = addr_to_func[decl.address];
  if (native_func) {
    CHECK_EQ(native_func->getFunctionType(), func_type);
    return native_func;
  }

  // By default we do not want to deal with function names until the very end of
  // lifting. Instead, we assign a temporary name based on the function's
  // starting address, its type, and its calling convention.
  std::stringstream ss;
  ss << "sub_" << std::hex << decl.address << '_'
     << type_specifier.EncodeToString(func_type,
                                      EncodingFormat::kValidSymbolCharsOnly)
     << '_' << std::dec << decl.calling_convention;

  const auto base_name = ss.str();
  func_name_to_address.emplace(base_name, decl.address);

  // Try to get it as an already named function.
  native_func = semantics_module->getFunction(base_name);
  if (native_func) {
    CHECK_EQ(native_func->getFunctionType(), func_type);
    return native_func;
  }

  native_func =
      llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                             base_name, semantics_module.get());
  native_func->setCallingConv(decl.calling_convention);
  native_func->removeFnAttr(llvm::Attribute::InlineHint);
  native_func->removeFnAttr(llvm::Attribute::AlwaysInline);
  native_func->addFnAttr(llvm::Attribute::NoInline);
  if (decl.is_noreturn) {
    native_func->addFnAttr(llvm::Attribute::NoReturn);
  }

  return native_func;
}

// Set up `native_func` to be able to call `lifted_func`. This means
// marshalling high-level argument types into lower-level values to pass into
// a stack-allocated `State` structure. This also involves providing initial
// default values for registers.
void FunctionLifter::CallLiftedFunctionFromNativeFunction(
    const FunctionDecl &decl) {
  if (!native_func->isDeclaration()) {
    return;
  }

  // Create a state structure and a stack frame in the native function
  // and we'll call the lifted function with that. The lifted function
  // will get inlined into this function.
  auto block = llvm::BasicBlock::Create(llvm_context, "", native_func);

  // Create a memory pointer.
  llvm::Value *mem_ptr = llvm::Constant::getNullValue(mem_ptr_type);

  // Stack-allocate and initialize the state pointer.
  auto native_state_ptr = AllocateAndInitializeStateStructure(block, decl.arch);

  auto pc_ptr = pc_reg->AddressOf(native_state_ptr, block);
  auto sp_ptr = sp_reg->AddressOf(native_state_ptr, block);

  llvm::IRBuilder<> ir(block);

  // Initialize the program counter.
  auto pc =
      options.program_counter_init_procedure(ir, address_type, func_address);
  ir.CreateStore(pc, pc_ptr);

  // Initialize the stack pointer.
  ir.CreateStore(options.stack_pointer_init_procedure(ir, sp_reg, func_address),
                 sp_ptr);

  auto &types = type_specifier.Dictionary();

  // Does this function have a return address? Most functions are provided a
  // return address on the stack, however the program entrypoint (usually
  // `_start`) won't have one. When we initialize the stack frame, we should
  // take note of this flag and in the case of the program entrypoint, omit the
  // symbolic return address from the stack frame.
  if (!decl.return_address.type->isVoidTy()) {
    auto ra =
        options.return_address_init_procedure(ir, address_type, func_address);

    mem_ptr = StoreNativeValue(ra, decl.return_address, types, intrinsics,
                               block, native_state_ptr, mem_ptr);
  }

  // Store the function parameters either into the state struct
  // or into memory (likely the stack).
  auto arg_index = 0u;
  for (auto &arg : native_func->args()) {
    const auto &param_decl = decl.params[arg_index++];
    mem_ptr = StoreNativeValue(&arg, param_decl, types, intrinsics, block,
                               native_state_ptr, mem_ptr);
  }

  llvm::Value *lifted_func_args[remill::kNumBlockArgs] = {};
  lifted_func_args[remill::kStatePointerArgNum] = native_state_ptr;
  lifted_func_args[remill::kMemoryPointerArgNum] = mem_ptr;
  lifted_func_args[remill::kPCArgNum] = pc;
  auto call_to_lifted_func = ir.CreateCall(lifted_func->getFunctionType(),
                                           lifted_func, lifted_func_args);
  if (decl.is_noreturn) {
    call_to_lifted_func->setDoesNotReturn();
  }
  mem_ptr = call_to_lifted_func;

  // Annotate all instructions leading up to and including the call of the
  // lifted function using the function's address.
  //
  // NOTE(pag): We don't annotate any of the subsequently created instructions
  //            for marshalling return values back out because there may be
  //            multiple return/tail-call sites in the function we've just
  //            lifted.
  AnnotateInstructions(block, pc_annotation_id, GetPCAnnotation(func_address));

  llvm::Value *ret_val = nullptr;

  if (decl.returns.size() == 1) {
    ret_val = LoadLiftedValue(decl.returns.front(), types, intrinsics, block,
                              native_state_ptr, mem_ptr);
    ir.SetInsertPoint(block);

  } else if (1 < decl.returns.size()) {
    ret_val = llvm::UndefValue::get(native_func->getReturnType());
    auto index = 0u;
    for (auto &ret_decl : decl.returns) {
      auto partial_ret_val = LoadLiftedValue(ret_decl, types, intrinsics, block,
                                             native_state_ptr, mem_ptr);
      ir.SetInsertPoint(block);
      unsigned indexes[] = {index};
      ret_val = ir.CreateInsertValue(ret_val, partial_ret_val, indexes);
      index += 1;
    }
  }

  auto memory_escape = GetMemoryEscapeFunc(intrinsics);
  llvm::Value *escape_args[] = {mem_ptr};
  ir.CreateCall(memory_escape, escape_args);

  if (ret_val) {
    ir.CreateRet(ret_val);
  } else {
    ir.CreateRetVoid();
  }
}


// In practice, lifted functions are not workable as is; we need to emulate
// `__attribute__((flatten))`, i.e. recursively inline as much as possible, so
// that all semantics and helpers are completely inlined.
void FunctionLifter::RecursivelyInlineLiftedFunctionIntoNativeFunction(void) {
  CHECK(!llvm::verifyModule(*this->native_func->getParent(), &llvm::errs()));
  this->RecursivelyInlineFunctionCallees(this->native_func);
}

// Lift a function. Will return `nullptr` if the memory is
// not accessible or executable.
llvm::Function *FunctionLifter::DeclareFunction(const FunctionDecl &decl) {

  // This is our higher-level function, i.e. it presents itself more like
  // a function compiled from C/C++, rather than being a three-argument Remill
  // function. In this function, we will stack-allocate a `State` structure,
  // then call a `lifted_func` below, which will embed the instruction
  // semantics.
  return GetOrDeclareFunction(decl);
}

CallableBasicBlockFunction
FunctionLifter::LiftBasicBlockFunction(const CodeBlock &blk) const {
  std::unique_ptr<SpecBlockContext> context =
      std::make_unique<SpecBlockContext>(
          this->curr_decl->GetBlockContext(blk.addr));

  return BasicBlockLifter::LiftBasicBlock(
      std::move(context), *this->curr_decl, blk, this->options,
      this->semantics_module.get(), this->type_specifier);
}


void FunctionLifter::VisitBlock(CodeBlock blk,
                                llvm::Value *lifted_function_state,
                                llvm::Value *abstract_stack) {
  auto llvm_blk = this->GetOrCreateBlock(blk.addr);
  llvm::IRBuilder<> builder(llvm_blk);


  auto bbfunc = this->LiftBasicBlockFunction(blk);

  CHECK(!llvm::verifyFunction(*bbfunc.GetFunction(), &llvm::errs()));

  bbfunc.CallBasicBlockFunction(builder, lifted_function_state, abstract_stack);
  CHECK(anvill::GetBasicBlockAddr(bbfunc.GetFunction()).has_value());

  auto pc = remill::LoadNextProgramCounter(llvm_blk, this->intrinsics);

  auto sw = builder.CreateSwitch(pc, this->invalid_successor_block);

  for (uint64_t succ : blk.outgoing_edges) {
    sw->addCase(llvm::ConstantInt::get(
                    llvm::cast<llvm::IntegerType>(this->address_type), succ),
                this->GetOrCreateBlock(succ));
  }
}

void FunctionLifter::VisitBlocks(llvm::Value *lifted_function_state,
                                 llvm::Value *abstract_stack) {
  DLOG(INFO) << "Num blocks for func " << std::hex << this->curr_decl->address
             << ": " << this->curr_decl->cfg.size();


  for (const auto &[addr, blk] : this->curr_decl->cfg) {
    DLOG(INFO) << "Visiting: " << std::hex << addr;
    this->VisitBlock(blk, lifted_function_state, abstract_stack);
  }

  // NOTE(Ian): some blocks may be empty ie. if the CFG communicates a possible transition to some undecodeable
  // bytes so here we check for block transfers that got added that we havent initialized and add an error
  // if we end up transferring there.
  for (auto &blks : this->lifted_func->getBasicBlockList()) {
    if (!blks.getTerminator()) {
      llvm::BranchInst::Create(this->invalid_successor_block, &blks);
    }
  }
}


LiftedFunction FunctionLifter::CreateLiftedFunction(const std::string &name) {
  auto new_func =
      options.arch->DefineLiftedFunction(name, semantics_module.get());
  auto state_ptr = remill::NthArgument(new_func, remill::kStatePointerArgNum);
  auto pc_arg = remill::NthArgument(new_func, remill::kPCArgNum);
  auto mem_arg = remill::NthArgument(new_func, remill::kMemoryPointerArgNum);


  new_func->removeFnAttr(llvm::Attribute::NoInline);
  new_func->addFnAttr(llvm::Attribute::InlineHint);
  new_func->addFnAttr(llvm::Attribute::AlwaysInline);
  new_func->setLinkage(llvm::GlobalValue::InternalLinkage);

  return {new_func, state_ptr, pc_arg, mem_arg};
}
// Lift a function. Will return `nullptr` if the memory is
// not accessible or executable.
llvm::Function *FunctionLifter::LiftFunction(const FunctionDecl &decl) {
  addr_to_func.clear();
  edge_work_list.clear();
  addr_to_block.clear();
  this->op_lifter->ClearCache();
  curr_decl = &decl;
  curr_inst = nullptr;
  mem_ptr_ref = nullptr;
  func_address = decl.address;
  native_func = DeclareFunction(decl);
  pc_annotation = GetPCAnnotation(func_address);

  // Not a valid address, or memory isn't executable.
  auto [first_byte, first_byte_avail, first_byte_perms] =
      memory_provider.Query(func_address);
  if (!MemoryProvider::IsValidAddress(first_byte_avail) ||
      !MemoryProvider::IsExecutable(first_byte_perms)) {
    LOG(ERROR) << "Address is not valid for func " << std::hex << decl.address;
    return nullptr;
  }

  // This is our higher-level function, i.e. it presents itself more like
  // a function compiled from C/C++, rather than being a three-argument Remill
  // function. In this function, we will stack-allocate a `State` structure,
  // then call a `lifted_func` below, which will embed the instruction
  // semantics.
  native_func = GetOrDeclareFunction(decl);

  // Check if we already lifted this function. If so, do not re-lift it.
  if (!native_func->isDeclaration()) {
    return native_func;
  }

  if (decl.lift_as_decl) {
    return native_func;
  }

  // The address is valid, the memory is executable, but we don't actually have
  // the data available for lifting, so leave us with just a declaration.
  if (!MemoryProvider::HasByte(first_byte_avail)) {
    LOG(ERROR) << "Memprov does not have bytes for func: " << std::hex
               << decl.address;
    return native_func;
  }

  // Every lifted function starts as a clone of __remill_basic_block. That
  // prototype has multiple arguments (memory pointer, state pointer, program
  // counter). This extracts the state pointer.
  auto lifted_func_st =
      this->CreateLiftedFunction(native_func->getName().str() + ".lifted");
  lifted_func = lifted_func_st.func;


  invalid_successor_block =
      llvm::BasicBlock::Create(lifted_func_st.func->getContext(),
                               "invalid_successor", lifted_func_st.func);
  remill::AddTerminatingTailCall(invalid_successor_block, intrinsics.error,
                                 intrinsics);


  const auto pc = lifted_func_st.pc_arg;
  const auto entry_block = &(lifted_func->getEntryBlock());
  pc_reg_ref =
      this->op_lifter
          ->LoadRegAddress(entry_block, lifted_func_st.state_ptr, pc_reg->name)
          .first;
  next_pc_reg_ref = this->op_lifter
                        ->LoadRegAddress(entry_block, lifted_func_st.state_ptr,
                                         remill::kNextPCVariableName)
                        .first;
  sp_reg_ref =
      this->op_lifter
          ->LoadRegAddress(entry_block, lifted_func_st.state_ptr, sp_reg->name)
          .first;

  mem_ptr_ref = remill::LoadMemoryPointerRef(entry_block);

  // Force initialize both the `PC` and `NEXT_PC` from the `pc` argument.
  // On some architectures, `NEXT_PC` is a "pseudo-register", i.e. an `alloca`
  // inside of `__remill_basic_block`, of which `lifted_func` is a clone, and
  // so we want to ensure it gets reliably initialized before any lifted
  // instructions may depend upon it.
  llvm::IRBuilder<> ir(entry_block);
  ir.CreateStore(pc, next_pc_reg_ref);
  ir.CreateStore(pc, pc_reg_ref);


  auto abstract_stack = ir.CreateAlloca(
      AbstractStack::StackTypeFromSize(llvm_context, decl.maximum_depth),
      nullptr, "abstract_stack");
  // Add a branch between the first block of the lifted function, which sets
  // up some local variables, and the block that will contain the lifted
  // instruction.
  //
  // NOTE(pag): This also introduces the first element to the work list.
  //
  // TODO: This could be a thunk, that we are maybe lifting on purpose.
  //       How should control flow redirection behave in this case?
  auto entry_insn = this->GetOrCreateBlock(this->func_address);
  ir.CreateBr(entry_insn);

  AnnotateInstructions(entry_block, pc_annotation_id,
                       GetPCAnnotation(func_address));

  DLOG(INFO) << "Visiting insns";
  // Go lift all instructions!
  VisitBlocks(lifted_func_st.state_ptr, abstract_stack);

  CHECK(!llvm::verifyFunction(*this->lifted_func, &llvm::errs()));

  // Fill up `native_func` with a basic block and make it call `lifted_func`.
  // This creates things like the stack-allocated `State` structure.
  CallLiftedFunctionFromNativeFunction(decl);


  // The last stage is that we need to recursively inline all calls to semantics
  // functions into `native_func`.
  RecursivelyInlineLiftedFunctionIntoNativeFunction();

  return native_func;
}
// Returns the address of a named function.
std::optional<uint64_t>
FunctionLifter::AddressOfNamedFunction(const std::string &func_name) const {
  auto it = func_name_to_address.find(func_name);
  if (it == func_name_to_address.end()) {
    return std::nullopt;
  } else {
    return it->second;
  }
}

// Lifts the machine code function starting at address `decl.address`, and
// using the architecture of the lifter context, lifts the bytes into the
// context's module.
//
// Returns an `llvm::Function *` that is part of `options_.module`.
//
// NOTE(pag): If this function returns `nullptr` then it means that we cannot
//            lift the function (e.g. bad address, or non-executable memory).
llvm::Function *EntityLifter::LiftEntity(const FunctionDecl &decl) const {
  auto &func_lifter = impl->function_lifter;
  llvm::Module *const module = impl->options.module;
  llvm::LLVMContext &context = module->getContext();
  llvm::FunctionType *module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, context));
  llvm::Function *found_by_type = nullptr;
  llvm::Function *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // function at the corresponding address.
  impl->ForEachEntityAtAddress(decl.address, [&](llvm::Constant *gv) {
    if (auto func = llvm::dyn_cast<llvm::Function>(gv)) {
      if (func->getFunctionType() == module_func_type) {
        found_by_type = func;

      } else if (!found_by_address) {
        found_by_address = func;
      }
    }
  });

  LOG_IF(ERROR, found_by_address != nullptr)
      << "Ignoring existing version of function at address " << std::hex
      << decl.address << " with type "
      << remill::LLVMThingToString(found_by_address->getFunctionType())
      << " and lifting function with type "
      << remill::LLVMThingToString(module_func_type);

  // Try to lift the function. If we failed then return the function found
  // with a matching type, if any.
  const auto func = func_lifter.LiftFunction(decl);
  if (!func) {
    return found_by_type;
  }

  // Make sure the names match up so that when we copy `func` into
  // `options.module`, we end up copying into the right function.
  std::string old_name;
  if (found_by_type && found_by_type->getName() != func->getName()) {
    old_name = found_by_type->getName().str();
    found_by_type->setName(func->getName());
  }

  // Add the function to the entity lifter's target module.
  const auto func_in_target_module =
      func_lifter.AddFunctionToContext(func, decl, *impl);

  // If we had a previous declaration/definition, then we want to make sure
  // that we replaced its body, and we also want to make sure that if our
  // default function naming scheme is not using the same name as the function
  // then we fixup its name to be its prior name. This could happen if the
  // user renames a function between lifts/declares.
  if (found_by_type) {
    CHECK_EQ(func_in_target_module, found_by_type);
    if (!old_name.empty() && func_in_target_module->getName() != old_name) {
      func_in_target_module->setName(old_name);
    }
  }


  return func_in_target_module;
}

// Declare the function associated with `decl` in the context's module.
//
// NOTE(pag): If this function returns `nullptr` then it means that we cannot
//            declare the function (e.g. bad address, or non-executable
//            memory).
llvm::Function *EntityLifter::DeclareEntity(const FunctionDecl &decl) const {
  auto &func_lifter = impl->function_lifter;
  llvm::Module *const module = impl->options.module;
  llvm::LLVMContext &context = module->getContext();
  llvm::FunctionType *module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(decl.type, context));

  llvm::Function *found_by_type = nullptr;
  llvm::Function *found_by_address = nullptr;

  // Go try to figure out if we've already got a declaration for this specific
  // function at the corresponding address.
  //
  // TODO(pag): Refactor out this copypasta.
  impl->ForEachEntityAtAddress(decl.address, [&](llvm::Constant *gv) {
    if (auto func = llvm::dyn_cast<llvm::Function>(gv)) {
      if (func->getFunctionType() == module_func_type) {
        found_by_type = func;

      } else if (!found_by_address) {
        found_by_address = func;
      }
    }
  });

  // We've already got a declaration for this function; return it.
  if (found_by_type) {
    return found_by_type;
  }

  LOG_IF(ERROR, found_by_address != nullptr)
      << "Ignoring existing version of function at address " << std::hex
      << decl.address << " with type "
      << remill::LLVMThingToString(found_by_address->getFunctionType())
      << " and declaring function with type "
      << remill::LLVMThingToString(module_func_type);

  if (const auto func = func_lifter.DeclareFunction(decl)) {
    DCHECK(!module->getFunction(func->getName()));
    return func_lifter.AddFunctionToContext(func, decl, *impl);
  } else {
    return nullptr;
  }
}

namespace {

// Erase the body of a function.
static void EraseFunctionBody(llvm::Function *func) {
  std::vector<llvm::BasicBlock *> blocks_to_erase;
  std::vector<llvm::Instruction *> insts_to_erase;

  // Collect stuff for erasure.
  for (auto &block : *func) {
    block.dropAllReferences();
  }

  while (!func->isDeclaration()) {
    func->back().eraseFromParent();
  }
}

}  // namespace

// Update the associated entity lifter with information about this
// function, and copy the function into the context's module. Returns the
// version of `func` inside the module of the lifter context.
llvm::Function *
FunctionLifter::AddFunctionToContext(llvm::Function *func,
                                     const FunctionDecl &decl,
                                     EntityLifterImpl &lifter_context) const {

  const auto target_module = options.module;
  auto &module_context = target_module->getContext();


  if (!func->isDeclaration()) {
    for (auto &[block_addr, block] : decl.cfg) {
      std::string name = "basic_block_func" + std::to_string(block_addr);
      auto new_version = target_module->getFunction(name);
      if (!new_version) {
        auto old_version = semantics_module->getFunction(name);
        auto type =
            llvm::dyn_cast<llvm::FunctionType>(remill::RecontextualizeType(
                old_version->getFunctionType(), module_context));
        new_version = llvm::Function::Create(
            type, llvm::GlobalValue::ExternalLinkage, name, target_module);
        remill::CloneFunctionInto(old_version, new_version);
        new_version->setMetadata(
            kBasicBlockMetadata,
            this->GetAddrAnnotation(block_addr, module_context));
        CHECK(anvill::GetBasicBlockAddr(new_version).has_value());
      }
    }
  }

  const auto name = func->getName().str();
  const auto module_func_type = llvm::dyn_cast<llvm::FunctionType>(
      remill::RecontextualizeType(func->getFunctionType(), module_context));

  // Try to get the old version of the function by name. If it exists and has
  // a body then erase it. As much as possible, we want to maintain referential
  // transparency w.r.t. user code, and not suddenly delete things out from
  // under them.
  auto new_version = target_module->getFunction(name);
  if (new_version) {
    CHECK_EQ(module_func_type, new_version->getFunctionType());
    if (!new_version->isDeclaration()) {
      EraseFunctionBody(new_version);
      CHECK(new_version->isDeclaration());
    }

    // It's possible that we've lifted this function before, but that it was
    // renamed by user code, and so the above check failed. Go check for that.
  } else {
    lifter_context.ForEachEntityAtAddress(
        decl.address, [&](llvm::Constant *gv) {
          if (auto gv_func = llvm::dyn_cast<llvm::Function>(gv);
              gv_func && gv_func->getFunctionType() == module_func_type) {
            CHECK(!new_version);
            new_version = gv_func;
          }
        });
  }

  // This is the first time we're lifting this function, or even the first time
  // we're seeing a reference to it, so we will need to make the function in
  // the target module.
  if (!new_version) {
    new_version = llvm::Function::Create(module_func_type,
                                         llvm::GlobalValue::ExternalLinkage,
                                         name, target_module);
  }

  remill::CloneFunctionInto(func, new_version);

  // Now that we're done, erase the body of `func`. We keep `func` around
  // just in case it will be needed in future lifts.
  EraseFunctionBody(func);

  if (auto func_annotation = GetPCAnnotation(decl.address)) {
    new_version->setMetadata(pc_annotation_id, func_annotation);
  }

  // Update the context to keep its internal concepts of what LLVM objects
  // correspond with which native binary addresses.
  lifter_context.AddEntity(new_version, decl.address);

  // The function we just lifted may call other functions, so we need to go
  // find those and also use them to update the context.
  for (auto &inst : llvm::instructions(*new_version)) {
    if (auto call = llvm::dyn_cast<llvm::CallBase>(&inst)) {
      if (auto called_func = call->getCalledFunction()) {
        const auto called_func_name = called_func->getName().str();
        auto called_func_addr = AddressOfNamedFunction(called_func_name);
        if (called_func_addr) {
          lifter_context.AddEntity(called_func, *called_func_addr);
        }
      }
    }
  }

  return new_version;
}

}  // namespace anvill
