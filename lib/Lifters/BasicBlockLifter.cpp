#include "BasicBlockLifter.h"

#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/Util.h>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <vector>

#include "Lifters/CodeLifter.h"
#include "Lifters/FunctionLifter.h"
#include "anvill/Declarations.h"
#include "anvill/Optimize.h"

namespace anvill {

void BasicBlockLifter::LiftBasicBlockFunction() {
  auto bbfunc = this->CreateBasicBlockFunction();
  this->LiftInstructionsIntoLiftedFunction();
  CHECK(!llvm::verifyFunction(*this->lifted_func, &llvm::errs()));
  CHECK(!llvm::verifyFunction(*bbfunc.func, &llvm::errs()));

  this->RecursivelyInlineFunctionCallees(bbfunc.func);
}


remill::DecodingContext BasicBlockLifter::ApplyContextAssignments(
    const std::unordered_map<std::string, uint64_t> &assignments,
    remill::DecodingContext prev_context) {
  for (const auto &[k, v] : assignments) {
    prev_context.UpdateContextReg(k, v);
  }
  return prev_context;
}


llvm::CallInst *BasicBlockLifter::AddCallFromBasicBlockFunctionToLifted(
    llvm::BasicBlock *source_block, llvm::Function *dest_func,
    const remill::IntrinsicTable &intrinsics, llvm::Value *pc_hint) {
  auto func = source_block->getParent();
  llvm::IRBuilder<> ir(source_block);
  std::array<llvm::Value *, remill::kNumBlockArgs> args;
  args[remill::kMemoryPointerArgNum] =
      NthArgument(func, remill::kMemoryPointerArgNum);
  args[remill::kStatePointerArgNum] =
      NthArgument(func, remill::kStatePointerArgNum);

  if (pc_hint) {
    args[remill::kPCArgNum] = pc_hint;
  } else {
    args[remill::kPCArgNum] =
        remill::LoadNextProgramCounter(source_block, this->intrinsics);
  }

  return ir.CreateCall(dest_func, args);
}


// Helper to figure out the address where execution will resume after a
// function call. In practice this is the instruction following the function
// call, encoded in `inst.branch_not_taken_pc`. However, SPARC has a terrible
// ABI where they inject an invalid instruction following some calls as a way
// of communicating to the callee that they should return an object of a
// particular, hard-coded size. Thus, we want to actually identify then ignore
// that instruction, and present the following address for where execution
// should resume after a `call`.
std::pair<uint64_t, llvm::Value *>
BasicBlockLifter::LoadFunctionReturnAddress(const remill::Instruction &inst,
                                            llvm::BasicBlock *block) {

  const auto pc = inst.branch_not_taken_pc;

  // The semantics for handling a call save the expected return program counter
  // into a local variable.
  auto ret_pc = this->op_lifter->LoadRegValue(block, state_ptr,
                                              remill::kReturnPCVariableName);
  if (!is_sparc) {
    return {pc, ret_pc};
  }

  uint8_t bytes[4] = {};

  for (auto i = 0u; i < 4u; ++i) {
    auto [byte, accessible, perms] = memory_provider.Query(pc + i);
    switch (accessible) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kUnavailable:
        LOG(ERROR)
            << "Byte at address " << std::hex << (pc + i)
            << " is not available for inspection to figure out return address "
            << " of call instruction at address " << pc << std::dec;
        return {pc, ret_pc};

      default: bytes[i] = byte; break;
    }

    switch (perms) {
      case BytePermission::kUnknown:
      case BytePermission::kReadableExecutable:
      case BytePermission::kReadableWritableExecutable: break;
      case BytePermission::kReadable:
      case BytePermission::kReadableWritable:
        LOG(ERROR)
            << "Byte at address " << std::hex << (pc + i) << " being inspected "
            << "to figure out return address of call instruction at address "
            << pc << " is not executable" << std::dec;
        return {pc, ret_pc};
    }
  }

  union Format0a {
    uint32_t flat;
    struct {
      uint32_t imm22 : 22;
      uint32_t op2 : 3;
      uint32_t rd : 5;
      uint32_t op : 2;
    } u __attribute__((packed));
  } __attribute__((packed)) enc = {};
  static_assert(sizeof(Format0a) == 4, " ");

  enc.flat |= bytes[0];
  enc.flat <<= 8;
  enc.flat |= bytes[1];
  enc.flat <<= 8;
  enc.flat |= bytes[2];
  enc.flat <<= 8;
  enc.flat |= bytes[3];

  // This looks like an `unimp <imm22>` instruction, where the `imm22` encodes
  // the size of the value to return. See "Specificationming Note" in v8 manual,
  // B.31, p 137.
  //
  // TODO(pag, kumarak): Does a zero value in `enc.u.imm22` imply a no-return
  //                     function? Try this on Compiler Explorer!
  if (!enc.u.op && !enc.u.op2) {
    LOG(INFO) << "Found structure return of size " << enc.u.imm22 << " to "
              << std::hex << pc << " at " << inst.pc << std::dec;

    llvm::IRBuilder<> ir(block);
    return {pc + 4u,
            ir.CreateAdd(ret_pc, llvm::ConstantInt::get(ret_pc->getType(), 4))};

  } else {
    return {pc, ret_pc};
  }
}


bool BasicBlockLifter::DoInterProceduralControlFlow(
    const remill::Instruction &insn, llvm::BasicBlock *block,
    const anvill::ControlFlowOverride &override) {
  // only handle inter-proc since intra-proc are handled implicitly by the CFG.
  llvm::IRBuilder<> builder(block);
  if (std::holds_alternative<anvill::Call>(override)) {
    auto cc = std::get<anvill::Call>(override);

    if (cc.target_address.has_value()) {
      this->AddCallFromBasicBlockFunctionToLifted(
          block, this->intrinsics.function_call, this->intrinsics,
          this->options.program_counter_init_procedure(
              builder, this->address_type, *cc.target_address));
    } else {
      this->AddCallFromBasicBlockFunctionToLifted(
          block, this->intrinsics.function_call, this->intrinsics);
    }
    if (!cc.stop) {
      auto [_, raddr] = this->LoadFunctionReturnAddress(insn, block);
      auto npc = remill::LoadNextProgramCounterRef(block);
      auto pc = remill::LoadProgramCounterRef(block);
      builder.CreateStore(raddr, npc);
      builder.CreateStore(raddr, pc);
    } else {
      remill::AddTerminatingTailCall(block, intrinsics.error, intrinsics);
    }
    return !cc.stop;
  } else if (std::holds_alternative<anvill::Return>(override)) {
    remill::AddTerminatingTailCall(block, intrinsics.function_return,
                                   intrinsics);
    return false;
  }

  return true;
}


bool BasicBlockLifter::ApplyInterProceduralControlFlowOverride(
    const remill::Instruction &insn, llvm::BasicBlock *&block) {


  // if this instruction is conditional and interprocedural then we are going to split the block into a case were we do take it and a branch where we dont and then rejoin

  auto override = options.control_flow_provider.GetControlFlowOverride(insn.pc);

  if ((std::holds_alternative<anvill::Call>(override) ||
       std::holds_alternative<anvill::Return>(override))) {
    if (std::holds_alternative<remill::Instruction::ConditionalInstruction>(
            insn.flows)) {
      auto btaken = remill::LoadBranchTaken(block);
      llvm::IRBuilder<> builder(block);
      auto do_control_flow =
          llvm::BasicBlock::Create(block->getContext(), "", block->getParent());
      auto continuation =
          llvm::BasicBlock::Create(block->getContext(), "", block->getParent());
      builder.CreateCondBr(btaken, do_control_flow, continuation);

      // if the interprocedural control flow block isnt terminal link it back up
      if (this->DoInterProceduralControlFlow(insn, do_control_flow, override)) {
        llvm::BranchInst::Create(continuation, do_control_flow);
      }

      block = continuation;
      return true;
    } else {
      return this->DoInterProceduralControlFlow(insn, block, override);
    }
  }

  return true;
}

remill::DecodingContext
BasicBlockLifter::CreateDecodingContext(const CodeBlock &blk) {
  auto init_context = this->options.arch->CreateInitialContext();
  return this->ApplyContextAssignments(blk.context_assignments,
                                       std::move(init_context));
}

// Try to decode an instruction at address `addr` into `*inst_out`. Returns
// the context map of the decoded instruction if successful and std::nullopt otherwise. `is_delayed` tells the decoder
// whether or not the instruction being decoded is being decoded inside of a
// delay slot of another instruction.
bool BasicBlockLifter::DecodeInstructionInto(const uint64_t addr,
                                             bool is_delayed,
                                             remill::Instruction *inst_out,
                                             remill::DecodingContext context) {
  static const auto max_inst_size = options.arch->MaxInstructionSize(context);
  inst_out->Reset();

  // Read the maximum number of bytes possible for instructions on this
  // architecture. For x86(-64), this is 15 bytes, whereas for fixed-width
  // architectures like AArch32/AArch64 and SPARC32/SPARC64, this is 4 bytes.
  inst_out->bytes.reserve(max_inst_size);

  auto accumulate_inst_byte = [=](auto byte, auto accessible, auto perms) {
    switch (accessible) {
      case ByteAvailability::kUnknown:
      case ByteAvailability::kUnavailable: return false;
      default:
        switch (perms) {
          case BytePermission::kUnknown:
          case BytePermission::kReadableExecutable:
          case BytePermission::kReadableWritableExecutable:
            inst_out->bytes.push_back(static_cast<char>(byte));
            return true;
          case BytePermission::kReadable:
          case BytePermission::kReadableWritable: return false;
        }
    }
  };

  for (auto i = 0u; i < max_inst_size; ++i) {
    if (!std::apply(accumulate_inst_byte, memory_provider.Query(addr + i))) {
      break;
    }
  }

  if (is_delayed) {
    return options.arch->DecodeDelayedInstruction(
        addr, inst_out->bytes, *inst_out, std::move(context));
  } else {
    return options.arch->DecodeInstruction(addr, inst_out->bytes, *inst_out,
                                           std::move(context));
  }
}


void BasicBlockLifter::LiftInstructionsIntoLiftedFunction() {
  auto entry_block = &this->lifted_func->getEntryBlock();

  auto bb = llvm::BasicBlock::Create(this->lifted_func->getContext(), "",
                                     this->lifted_func);


  llvm::BranchInst::Create(bb, entry_block);

  remill::Instruction inst;

  auto reached_addr = this->block_def.addr;
  // TODO(Ian): use a different context

  auto init_context = this->CreateDecodingContext(this->block_def);

  LOG(INFO) << "Decoding block at addr: " << std::hex << this->block_def.addr
            << " with size " << this->block_def.size;
  bool ended_on_terminal = false;
  while (reached_addr < this->block_def.addr + this->block_def.size &&
         !ended_on_terminal) {
    auto addr = reached_addr;
    LOG(INFO) << "Decoding at addr " << std::hex << addr;
    auto res = this->DecodeInstructionInto(addr, false, &inst, init_context);
    if (!res) {
      remill::AddTerminatingTailCall(bb, this->intrinsics.error,
                                     this->intrinsics);
      LOG(ERROR) << "Failed to decode insn in block " << std::hex << addr;
      return;
    }

    reached_addr += inst.bytes.size();

    // Even when something isn't supported or is invalid, we still lift
    // a call to a semantic, e.g.`INVALID_INSTRUCTION`, so we really want
    // to treat instruction lifting as an operation that can't fail.


    std::ignore = inst.GetLifter()->LiftIntoBlock(
        inst, bb, this->lifted_func->getArg(remill::kStatePointerArgNum),
        false /* is_delayed */);

    ended_on_terminal =
        !this->ApplyInterProceduralControlFlowOverride(inst, bb);
    LOG_IF(INFO, ended_on_terminal)
        << "On terminal at addr: " << std::hex << addr;
  }

  if (!ended_on_terminal) {
    llvm::IRBuilder<> builder(bb);

    builder.CreateStore(remill::LoadNextProgramCounter(bb, this->intrinsics),
                        this->lifted_func->getArg(remill::kNumBlockArgs));


    llvm::ReturnInst::Create(
        bb->getContext(), remill::LoadMemoryPointer(bb, this->intrinsics), bb);
  }
}


llvm::MDNode *BasicBlockLifter::GetBasicBlockAnnotation(uint64_t addr) const {
  return this->GetAddrAnnotation(addr, this->semantics_module->getContext());
}


llvm::Function *BasicBlockLifter::DeclareBasicBlockFunction() {
  std::string name_ = "basic_block_func" + std::to_string(block_def.addr);
  auto &context = semantics_module->getContext();

  auto var_struct_ty = this->var_struct_ty;
  llvm::FunctionType *lifted_func_type =
      llvm::dyn_cast<llvm::FunctionType>(remill::RecontextualizeType(
          this->options.arch->LiftedFunctionType(), context));

  std::vector<llvm::Type *> params = std::vector(
      lifted_func_type->param_begin(), lifted_func_type->param_end());

  // pointer to state pointer
  params[remill::kStatePointerArgNum] = llvm::PointerType::get(context, 0);

  //next_pc_out
  params.push_back(llvm::PointerType::get(context, 0));


  for (size_t i = 0; i < var_struct_ty->getNumElements(); i++) {
    // pointer to each param
    params.push_back(llvm::PointerType::get(context, 0));
  }


  auto ret_type = this->block_context->ReturnValue();
  llvm::FunctionType *func_type = llvm::FunctionType::get(
      this->flifter.curr_decl->type->getReturnType(), params, false);


  llvm::StringRef name(name_.data(), name_.size());
  return llvm::Function::Create(func_type, llvm::GlobalValue::ExternalLinkage,
                                0u, name, semantics_module);
}

BasicBlockFunction BasicBlockLifter::CreateBasicBlockFunction() {
  auto func = this->bb_func;
  func->setMetadata(anvill::kBasicBlockMetadata,
                    GetBasicBlockAnnotation(block_def.addr));

  auto &context = this->semantics_module->getContext();
  llvm::FunctionType *lifted_func_type =
      llvm::dyn_cast<llvm::FunctionType>(remill::RecontextualizeType(
          this->options.arch->LiftedFunctionType(), context));
  auto start_ind = lifted_func_type->getNumParams() + 1;
  for (auto v : this->block_context->LiveParamsAtEntryAndExit()) {
    auto arg = remill::NthArgument(func, start_ind);
    if (!v.param.name.empty()) {
      arg->setName(v.param.name);
    }

    if (v.param.reg) {
      // Registers should not have aliases
      arg->addAttr(llvm::Attribute::get(llvm_context,
                                        llvm::Attribute::AttrKind::NoAlias));
    }
    // TODO(Ian): If we can eliminate the stack then we also are able to declare more no aliases here, not sure the
    // best way to handle this

    start_ind += 1;
  }

  auto memory = remill::NthArgument(func, remill::kMemoryPointerArgNum);
  auto state = remill::NthArgument(func, remill::kStatePointerArgNum);
  auto pc = remill::NthArgument(func, remill::kPCArgNum);
  auto next_pc_out = remill::NthArgument(func, remill::kNumBlockArgs);

  memory->setName("memory");
  pc->setName("program_counter");
  next_pc_out->setName("next_pc_out");
  state->setName("stack");


  auto liftedty = this->options.arch->LiftedFunctionType();

  std::vector<llvm::Type *> new_params;
  new_params.reserve(liftedty->getNumParams() + 1);

  for (auto param : liftedty->params()) {
    new_params.push_back(param);
  }
  new_params.push_back(llvm::PointerType::get(context, 0));


  llvm::FunctionType *new_func_type = llvm::FunctionType::get(
      lifted_func_type->getReturnType(), new_params, false);


  this->lifted_func = llvm::Function::Create(
      new_func_type, llvm::GlobalValue::ExternalLinkage, 0u,
      std::string(func->getName()) + "lowlift", this->semantics_module);

  options.arch->InitializeEmptyLiftedFunction(this->lifted_func);


  llvm::BasicBlock::Create(context, "", func);
  auto &blk = func->getEntryBlock();
  llvm::IRBuilder<> ir(&blk);
  auto mem_var = ir.CreateAlloca(memory->getType(), nullptr, "MEMORY");
  ir.CreateStore(memory, mem_var);

  this->state_ptr =
      this->AllocateAndInitializeStateStructure(&blk, options.arch);

  // Put registers that are referencing the stack in terms of their displacement so that we
  // Can resolve these stack references later .

  auto sp_value =
      options.stack_pointer_init_procedure(ir, sp_reg, this->block_def.addr);
  auto sp_ptr = sp_reg->AddressOf(this->state_ptr, ir);
  // Initialize the stack pointer.
  ir.CreateStore(sp_value, sp_ptr);

  auto stack_offsets = this->block_context->GetStackOffsets();
  for (auto &reg_off : stack_offsets.affine_equalities) {
    auto new_value = LifterOptions::SymbolicStackPointerInitWithOffset(
        ir, this->sp_reg, this->block_def.addr, reg_off.stack_offset);
    auto nmem = StoreNativeValue(
        new_value, reg_off.target_value, type_provider.Dictionary(), intrinsics,
        ir, this->state_ptr, remill::LoadMemoryPointer(ir, intrinsics));
    ir.CreateStore(nmem, remill::LoadMemoryPointerRef(ir.GetInsertBlock()));
  }

  PointerProvider ptr_provider = [this, func](size_t index) -> llvm::Value * {
    return this->ProvidePointerFromFunctionArgs(func, index);
  };


  LOG(INFO) << "Live values at entry to function "
            << this->block_context->LiveBBParamsAtEntry().size();
  this->UnpackLiveValues(ir, ptr_provider, this->state_ptr,
                         this->block_context->LiveBBParamsAtEntry());

  auto pc_arg = remill::NthArgument(func, remill::kPCArgNum);
  auto mem_arg = remill::NthArgument(func, remill::kMemoryPointerArgNum);

  func->addFnAttr(llvm::Attribute::NoInline);
  //func->setLinkage(llvm::GlobalValue::InternalLinkage);

  auto mem_res = remill::LoadMemoryPointer(ir, this->intrinsics);

  // Initialize the program counter
  auto pc_ptr = pc_reg->AddressOf(this->state_ptr, ir);
  auto pc_val = this->options.program_counter_init_procedure(
      ir, this->address_type, this->block_def.addr);
  ir.CreateStore(pc_val, pc_ptr);

  std::array<llvm::Value *, remill::kNumBlockArgs + 1> args = {
      this->state_ptr, pc_val, mem_res, next_pc_out};

  auto ret_mem = ir.CreateCall(this->lifted_func, args);
  ir.CreateStore(ret_mem, mem_var);

  this->PackLiveValues(ir, this->state_ptr, ptr_provider,
                       this->block_context->LiveBBParamsAtExit());


  CHECK(ir.GetInsertPoint() == func->getEntryBlock().end());


  BasicBlockFunction bbf{func, pc_arg, mem_arg, next_pc_out, state};

  TerminateBasicBlockFunction(ir, ret_mem, bbf);

  return bbf;
}

// Setup the returns for this function we tail call all successors
void BasicBlockLifter::TerminateBasicBlockFunction(
    llvm::IRBuilder<> &ir, llvm::Value *next_mem,
    const BasicBlockFunction &bbfunc) {
  this->invalid_successor_block = llvm::BasicBlock::Create(
      this->bb_func->getContext(), "invalid_successor", this->bb_func);

  // TODO(Ian): maybe want to call remill_error here
  new llvm::UnreachableInst(next_mem->getContext(),
                            this->invalid_successor_block);

  auto pc = ir.CreateLoad(address_type, bbfunc.next_pc_out_param);
  auto sw = ir.CreateSwitch(pc, this->invalid_successor_block);

  for (auto e : this->block_def.outgoing_edges) {
    auto succ_const = llvm::ConstantInt::get(
        llvm::cast<llvm::IntegerType>(this->address_type), e);

    auto calling_bb =
        llvm::BasicBlock::Create(next_mem->getContext(), "", bbfunc.func);
    llvm::IRBuilder<> calling_bb_builder(calling_bb);
    auto &child_lifter = this->flifter.GetOrCreateBasicBlockLifter(e);
    child_lifter.CallBasicBlockFunction(calling_bb_builder, this->state_ptr,
                                        bbfunc.stack, next_mem,
                                        bbfunc.next_pc_out_param);
    sw->addCase(succ_const, calling_bb);
  }
}


llvm::StructType *BasicBlockLifter::StructTypeFromVars() const {
  return this->block_context->StructTypeFromVars(this->llvm_context);
}

// Packs in scope variables into a struct
void BasicBlockLifter::PackLiveValues(
    llvm::IRBuilder<> &bldr, llvm::Value *from_state_ptr,
    PointerProvider into_vars,
    const std::vector<BasicBlockVariable> &decls) const {

  for (auto decl : decls) {

    if (!decl.param.mem_reg) {
      auto ptr = into_vars(decl.index);

      auto state_loaded_value = LoadLiftedValue(
          decl.param, this->type_provider.Dictionary(), this->intrinsics, bldr,
          from_state_ptr, remill::LoadMemoryPointer(bldr, this->intrinsics));

      bldr.CreateStore(state_loaded_value, ptr);
    }
  }
}

void BasicBlockLifter::UnpackLiveValues(
    llvm::IRBuilder<> &bldr, PointerProvider returned_value,
    llvm::Value *into_state_ptr,
    const std::vector<BasicBlockVariable> &decls) const {
  auto blk = bldr.GetInsertBlock();

  for (auto decl : decls) {
    // is this how we want to do this.... now the value really doesnt live in memory anywhere but the frame.
    if (!decl.param.mem_reg) {
      auto ptr = returned_value(decl.index);
      if (auto insn = llvm::dyn_cast<llvm::Instruction>(ptr)) {
        insn->setMetadata("anvill.type", this->type_specifier.EncodeToMetadata(
                                             decl.param.spec_type));
      }
      auto loaded_var_val =
          bldr.CreateLoad(decl.param.type, ptr, decl.param.name);

      auto mem_ptr = remill::LoadMemoryPointer(bldr, this->intrinsics);
      auto new_mem_ptr = StoreNativeValue(
          loaded_var_val, decl.param, this->type_provider.Dictionary(),
          this->intrinsics, bldr, into_state_ptr, mem_ptr);
      bldr.SetInsertPoint(bldr.GetInsertBlock());

      bldr.CreateStore(new_mem_ptr,
                       remill::LoadMemoryPointerRef(bldr.GetInsertBlock()));
    }
  }
  CHECK(bldr.GetInsertPoint() == blk->end());
}


// TODO(Ian): dependent on calling context we need fetch the memory and next program counter
// ref either from the args or from the parent func state
void BasicBlockLifter::CallBasicBlockFunction(
    llvm::IRBuilder<> &builder, llvm::Value *parent_state,
    llvm::Value *parent_stack, llvm::Value *memory_pointer,
    llvm::Value *program_pointer_ref) const {


  std::vector<llvm::Value *> args(remill::kNumBlockArgs + 1);
  auto out_param_locals = builder.CreateAlloca(this->var_struct_ty);
  args[0] = parent_stack;

  args[remill::kPCArgNum] = options.program_counter_init_procedure(
      builder, this->address_type, block_def.addr);
  args[remill::kMemoryPointerArgNum] = memory_pointer;

  args[remill::kNumBlockArgs] = program_pointer_ref;

  auto bbvars = this->block_context->LiveParamsAtEntryAndExit();

  AbstractStack stack(
      builder.getContext(), {{decl.maximum_depth, parent_stack}},
      this->options.stack_frame_recovery_options.stack_grows_down,
      decl.GetPointerDisplacement());
  PointerProvider ptr_provider = [&builder, this, out_param_locals, &bbvars,
                                  &stack](size_t index) -> llvm::Value * {
    auto repr_var = bbvars[index];
    LOG(INFO) << "Lifting: " << repr_var.param.name << " for call";
    if (repr_var.param.mem_reg) {
      auto stack_ptr = stack.PointerToStackMemberFromOffset(
          builder, repr_var.param.mem_offset);
      if (stack_ptr) {
        return *stack_ptr;
      } else {
        LOG(FATAL)
            << "Unable to create a ptr to the stack, the stack is too small to represent the param.";
      }
    }
    return this->ProvidePointerFromStruct(builder, out_param_locals, index);
  };

  this->PackLiveValues(builder, parent_state, ptr_provider,
                       this->block_context->LiveBBParamsAtEntry());


  for (size_t ind = 0;
       ind < this->block_context->LiveParamsAtEntryAndExit().size(); ind++) {
    auto ptr = ptr_provider(ind);
    CHECK(ptr != nullptr);
    args.push_back(ptr);
  }

  auto retval = builder.CreateCall(bb_func, args);
  retval->setTailCall(true);

  builder.CreateRet(retval);
}


BasicBlockLifter::BasicBlockLifter(
    std::unique_ptr<BasicBlockContext> block_context, const FunctionDecl &decl,
    const CodeBlock &block_def, const LifterOptions &options_,
    llvm::Module *semantics_module, const TypeTranslator &type_specifier,
    FunctionLifter &func_lifter)
    : CodeLifter(options_, semantics_module, type_specifier),
      block_context(std::move(block_context)),
      block_def(block_def),
      decl(decl),
      flifter(func_lifter) {
  this->var_struct_ty = this->StructTypeFromVars();
  this->bb_func = this->DeclareBasicBlockFunction();
}


llvm::Value *BasicBlockLifter::ProvidePointerFromStruct(llvm::IRBuilder<> &ir,
                                                        llvm::Value *target_sty,
                                                        size_t index) const {
  auto i32 = llvm::IntegerType::get(llvm_context, 32);
  auto ptr = ir.CreateGEP(
      this->var_struct_ty, target_sty,
      {llvm::ConstantInt::get(i32, 0), llvm::ConstantInt::get(i32, index)});
  return ptr;
}

llvm::Value *
BasicBlockLifter::ProvidePointerFromFunctionArgs(llvm::Function *func,
                                                 size_t index) const {
  return anvill::ProvidePointerFromFunctionArgs(func, index, this->options,
                                                *this->block_context);
}


}  // namespace anvill
