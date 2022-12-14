/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "anvill/Utils.h"

#include <anvill/ABI.h>
#include <anvill/Declarations.h>
#include <anvill/Type.h>
#include <anvill/Utils.h>
#include <glog/logging.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/Casting.h>
#include <remill/Arch/Arch.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Util.h>

#include <optional>
#include <sstream>

namespace anvill {

// Adapt `src` to another type (likely an integer type) that is `dest_type`.
llvm::Value *AdaptToType(llvm::IRBuilderBase &ir, llvm::Value *src,
                         llvm::Type *dest_type) {
  const auto src_type = src->getType();
  if (src_type == dest_type) {
    return src;
  }

  if (src_type->isIntegerTy()) {
    if (dest_type->isIntegerTy()) {
      auto src_size = src_type->getPrimitiveSizeInBits();
      auto dest_size = dest_type->getPrimitiveSizeInBits();
      CHECK_NE(src_size, dest_size);
      if (src_size < dest_size) {
        auto dest = ir.CreateZExt(src, dest_type);
        CopyMetadataTo(src, dest);
        return dest;
      } else if (dest_size == 1u) {
        auto dest =
            ir.CreateICmpNE(src, llvm::ConstantInt::getNullValue(src_type));
        CopyMetadataTo(src, dest);
        return dest;
      } else {
        auto dest = ir.CreateTrunc(src, dest_type);
        CopyMetadataTo(src, dest);
        return dest;
      }

    } else if (auto dest_ptr_type =
                   llvm::dyn_cast<llvm::PointerType>(dest_type);
               dest_ptr_type) {
      auto inter_type = llvm::PointerType::get(ir.getContext(), 0);

      llvm::Value *inter_val = nullptr;
      if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(src); pti) {
        src = llvm::cast<llvm::Constant>(pti->getOperand(0));
        if (src->getType() == dest_type) {
          return src;
        } else {
          inter_val = ir.CreateBitCast(src, inter_type);
          CopyMetadataTo(src, inter_val);
        }

      } else {
        inter_val = ir.CreateIntToPtr(src, inter_type);
        CopyMetadataTo(src, inter_val);
      }

      if (inter_type->getAddressSpace() == dest_ptr_type->getAddressSpace()) {
        return inter_val;
      } else {
        auto dest = ir.CreateAddrSpaceCast(inter_val, dest_ptr_type);
        CopyMetadataTo(src, dest);
        return dest;
      }
    }

  } else if (auto src_ptr_type = llvm::dyn_cast<llvm::PointerType>(src_type);
             src_ptr_type) {

    // Cast the pointer to the other pointer type.
    if (auto dest_ptr_type = llvm::dyn_cast<llvm::PointerType>(dest_type);
        dest_ptr_type) {

      if (src_ptr_type->getAddressSpace() != dest_ptr_type->getAddressSpace()) {
        src_ptr_type = llvm::PointerType::get(ir.getContext(),
                                              dest_ptr_type->getAddressSpace());
        auto dest = ir.CreateAddrSpaceCast(src, src_ptr_type);
        CopyMetadataTo(src, dest);
        src = dest;
      }

      if (src_ptr_type == dest_ptr_type) {
        return src;
      } else {
        auto dest = ir.CreateBitCast(src, dest_ptr_type);
        CopyMetadataTo(src, dest);
        return dest;
      }

      // Convert the pointer to an integer.
    } else if (auto dest_int_type =
                   llvm::dyn_cast<llvm::IntegerType>(dest_type);
               dest_int_type) {
      if (src_ptr_type->getAddressSpace()) {
        src_ptr_type = llvm::PointerType::get(ir.getContext(), 0);
        auto dest = ir.CreateAddrSpaceCast(src, src_ptr_type);
        CopyMetadataTo(src, dest);
        src = dest;
      }

      const auto block = ir.GetInsertBlock();
      const auto func = block->getParent();
      const auto module = func->getParent();
      const auto &dl = module->getDataLayout();
      auto &context = module->getContext();
      auto dest = ir.CreatePtrToInt(
          src, llvm::Type::getIntNTy(context, dl.getPointerSizeInBits(0)));
      CopyMetadataTo(src, dest);
      return AdaptToType(ir, dest, dest_type);
    }

  } else if (src_type->isFloatTy()) {
    if (dest_type->isDoubleTy()) {
      return ir.CreateFPExt(src, dest_type);

    } else if (dest_type->isIntegerTy()) {
      const auto i32_type = llvm::Type::getInt32Ty(dest_type->getContext());
      return AdaptToType(ir, ir.CreateBitCast(src, i32_type), dest_type);
    }

  } else if (src_type->isDoubleTy()) {
    if (dest_type->isFloatTy()) {
      auto dest = ir.CreateFPTrunc(src, dest_type);
      CopyMetadataTo(src, dest);
      return dest;

    } else if (dest_type->isIntegerTy()) {
      const auto i64_type = llvm::Type::getInt64Ty(dest_type->getContext());
      auto dest = ir.CreateBitCast(src, i64_type);
      CopyMetadataTo(src, dest);
      return AdaptToType(ir, dest, dest_type);
    }
  }

  // If we want to change the type of a load, then we can change the type of
  // the loaded pointer.
  if (auto li = llvm::dyn_cast<llvm::LoadInst>(src)) {
    ir.SetInsertPoint(li);
    auto loaded_ptr = AdaptToType(
        ir, li->getPointerOperand(),
        llvm::PointerType::get(ir.getContext(), li->getPointerAddressSpace()));
    ir.SetInsertPoint(li);
    auto new_li = ir.CreateLoad(dest_type, loaded_ptr);
    new_li->setVolatile(li->isVolatile());
    new_li->setAtomic(li->getOrdering(), li->getSyncScopeID());
    new_li->setAlignment(li->getAlign());
    CopyMetadataTo(li, new_li);
    return new_li;
  }

  // Fall-through, we don't have a supported adaptor.
  return nullptr;
}

namespace {

// Unfold constant expressions by expanding them into their relevant
// instructions inline in the original module. This lets us deal uniformly
// in terms of instructions.
static void UnfoldConstantExpressions(llvm::Instruction *inst, llvm::Use &use) {
  const auto val = use.get();
  if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
    const auto ce_inst = ce->getAsInstruction();
    ce_inst->insertBefore(inst);
    ::anvill::UnfoldConstantExpressions(ce_inst);
    use.set(ce_inst);
  }
}

}  // namespace

// Looks for any constant expressions in the operands of `inst` and unfolds
// them into other instructions in the same block.
void UnfoldConstantExpressions(llvm::Instruction *inst) {
  for (auto &use : inst->operands()) {
    UnfoldConstantExpressions(inst, use);
  }
  if (llvm::CallInst *call = llvm::dyn_cast<llvm::CallInst>(inst)) {
    for (llvm::Use &use : call->args()) {
      UnfoldConstantExpressions(inst, use);
    }
  }
}

std::string CreateFunctionName(std::uint64_t addr) {
  std::stringstream ss;
  ss << "sub_" << std::hex << addr;
  return ss.str();
}

std::string CreateVariableName(std::uint64_t addr) {
  std::stringstream ss;
  ss << "data_" << std::hex << addr;
  return ss.str();
}

void CopyMetadataTo(llvm::Value *src, llvm::Value *dst) {
  if (src == dst) {
    return;
  }
  llvm::Instruction *src_inst = llvm::dyn_cast_or_null<llvm::Instruction>(src),
                    *dst_inst = llvm::dyn_cast_or_null<llvm::Instruction>(dst);
  if (!src_inst || !dst_inst) {
    return;
  }

  llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 16u> mds;
  src_inst->getAllMetadataOtherThanDebugLoc(mds);
  for (auto [id, node] : mds) {
    switch (id) {
      case llvm::LLVMContext::MD_tbaa:
      case llvm::LLVMContext::MD_tbaa_struct:
      case llvm::LLVMContext::MD_noalias:
      case llvm::LLVMContext::MD_alias_scope: break;
      default: dst_inst->setMetadata(id, node); break;
    }
  }
}

void CloneIntrinsicsFromModule(llvm::Module &from, llvm::Module &into) {
  //CHECK(&from.getContext() == &into.getContext());
  auto func = from.getFunction("__remill_intrinsics");
  if (!func) {
    LOG(FATAL) << "No intrinsics bundle in module";
  }

  if (into.getFunction("__remill_intrinsics")) {
    return;
  }

  auto nfunc = llvm::Function::Create(
      llvm::cast<llvm::FunctionType>(remill::RecontextualizeType(
          func->getFunctionType(), into.getContext())),
      llvm::GlobalValue::ExternalLinkage, func->getName(), into);

  remill::CloneFunctionInto(func, nfunc);
}

void StoreNativeValueToRegister(llvm::Value *native_val,
                                const remill::Register *reg,
                                const TypeDictionary &types,
                                const remill::IntrinsicTable &intrinsics,
                                llvm::IRBuilder<> &ir, llvm::Value *state_ptr) {
  auto func = ir.GetInsertBlock()->getParent();
  auto module = func->getParent();
  auto &context = module->getContext();

  auto reg_type = remill::RecontextualizeType(reg->type, context);
  auto ptr_to_reg = reg->AddressOf(state_ptr, ir);

  llvm::StoreInst *store = nullptr;

  auto adapted_val = types.ConvertValueToType(ir, native_val, reg_type);

  if (adapted_val) {
    store = ir.CreateStore(adapted_val, ptr_to_reg);

  } else {
    auto ptr = ir.CreateBitCast(ptr_to_reg,
                                llvm::PointerType::get(ir.getContext(), 0));
    CopyMetadataTo(native_val, ptr);
    store = ir.CreateStore(native_val, ptr);
  }
  CopyMetadataTo(native_val, store);
}

void StoreNativeValueToRegister(llvm::Value *native_val,
                                const remill::Register *reg,
                                const TypeDictionary &types,
                                const remill::IntrinsicTable &intrinsics,
                                llvm::BasicBlock *in_block,
                                llvm::Value *state_ptr) {
  llvm::IRBuilder<> ir(in_block);
  StoreNativeValueToRegister(native_val, reg, types, intrinsics, ir, state_ptr);
}


llvm::Value *StoreNativeValue(llvm::Value *native_val, const ValueDecl &decl,
                              const TypeDictionary &types,
                              const remill::IntrinsicTable &intrinsics,
                              llvm::IRBuilder<> &ir, llvm::Value *state_ptr,
                              llvm::Value *mem_ptr) {

  auto func = ir.GetInsertBlock()->getParent();
  auto module = func->getParent();
  auto &context = module->getContext();

  llvm::Type *decl_type = remill::RecontextualizeType(decl.type, context);

  CHECK_EQ(module, intrinsics.read_memory_8->getParent());
  CHECK_EQ(native_val->getType(), decl_type);

  // Store it to a register.
  if (decl.reg) {
    StoreNativeValueToRegister(native_val, decl.reg, types, intrinsics, ir,
                               state_ptr);
    return mem_ptr;

    // Store it to memory.
  } else if (decl.mem_reg) {
    auto mem_reg_type =
        remill::RecontextualizeType(decl.mem_reg->type, context);
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, ir);

    llvm::Value *addr = ir.CreateLoad(mem_reg_type, ptr_to_reg);
    CopyMetadataTo(native_val, addr);

    if (0ll < decl.mem_offset) {
      addr = ir.CreateAdd(
          addr, llvm::ConstantInt::get(
                    mem_reg_type, static_cast<std::uint64_t>(decl.mem_offset),
                    false));
      CopyMetadataTo(native_val, addr);

    } else if (0ll > decl.mem_offset) {
      addr = ir.CreateSub(
          addr, llvm::ConstantInt::get(
                    mem_reg_type, static_cast<std::uint64_t>(-decl.mem_offset),
                    false));
      CopyMetadataTo(native_val, addr);
    }

    return remill::StoreToMemory(intrinsics, ir, native_val, mem_ptr, addr);

    // Store to memory at an absolute offset.
  } else if (decl.mem_offset) {
    const auto addr = llvm::ConstantInt::get(
        remill::NthArgument(intrinsics.read_memory_8, 1u)->getType(),
        static_cast<std::uint64_t>(decl.mem_offset), false);
    return remill::StoreToMemory(intrinsics, ir, native_val, mem_ptr, addr);

  } else {
    return llvm::UndefValue::get(mem_ptr->getType());
  }
}

// Produce one or more instructions in `in_block` to store the
// native value `native_val` into the lifted state associated
// with `decl`.
llvm::Value *StoreNativeValue(llvm::Value *native_val, const ValueDecl &decl,
                              const TypeDictionary &types,
                              const remill::IntrinsicTable &intrinsics,
                              llvm::BasicBlock *in_block,
                              llvm::Value *state_ptr, llvm::Value *mem_ptr) {

  llvm::IRBuilder<> ir(in_block);
  return StoreNativeValue(native_val, decl, types, intrinsics, ir, state_ptr,
                          mem_ptr);
}


llvm::Value *LoadLiftedValue(const ValueDecl &decl, const TypeDictionary &types,
                             const remill::IntrinsicTable &intrinsics,
                             llvm::IRBuilder<> &ir, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr) {

  auto func = ir.GetInsertBlock()->getParent();
  auto module = func->getParent();
  auto &context = module->getContext();
  CHECK_EQ(module, intrinsics.read_memory_8->getParent());

  llvm::Type *decl_type = remill::RecontextualizeType(decl.type, context);

  // Load it out of a register.
  if (decl.reg) {
    auto reg_type = remill::RecontextualizeType(decl.reg->type, context);
    auto ptr_to_reg = decl.reg->AddressOf(state_ptr, ir);
    auto reg = ir.CreateLoad(reg_type, ptr_to_reg);
    CopyMetadataTo(mem_ptr, reg);
    auto adapted_val = types.ConvertValueToType(ir, reg, decl_type);

    if (adapted_val) {
      return adapted_val;
    } else {
      auto bc =
          ir.CreateBitCast(ptr_to_reg, llvm::PointerType::get(context, 0));
      auto li = ir.CreateLoad(decl_type, bc);
      CopyMetadataTo(mem_ptr, bc);
      CopyMetadataTo(mem_ptr, li);
      return li;
    }

    // Load it out of memory.
  } else if (decl.mem_reg) {
    auto mem_reg_type =
        remill::RecontextualizeType(decl.mem_reg->type, context);
    auto ptr_to_reg = decl.mem_reg->AddressOf(state_ptr, ir);
    llvm::Value *addr = ir.CreateLoad(mem_reg_type, ptr_to_reg);
    CopyMetadataTo(mem_ptr, addr);
    if (0ll < decl.mem_offset) {
      addr = ir.CreateAdd(
          addr, llvm::ConstantInt::get(
                    mem_reg_type, static_cast<std::uint64_t>(decl.mem_offset),
                    false));
      CopyMetadataTo(mem_ptr, addr);

    } else if (0ll > decl.mem_offset) {
      addr = ir.CreateSub(
          addr, llvm::ConstantInt::get(
                    mem_reg_type, static_cast<std::uint64_t>(-decl.mem_offset),
                    false));
      CopyMetadataTo(mem_ptr, addr);
    }

    auto val = remill::LoadFromMemory(intrinsics, ir, decl_type, mem_ptr, addr);

    return types.ConvertValueToType(ir, val, decl_type);

    // Store to memory at an absolute offset.
  } else if (decl.mem_offset) {
    const auto addr = llvm::ConstantInt::get(
        remill::NthArgument(intrinsics.read_memory_8, 1u)->getType(),
        static_cast<std::uint64_t>(decl.mem_offset), false);
    auto val = remill::LoadFromMemory(intrinsics, ir, decl_type, mem_ptr, addr);

    CopyMetadataTo(mem_ptr, val);
    return types.ConvertValueToType(ir, val, decl_type);

  } else {
    DLOG(ERROR) << "Unable to load lifted value of type: "
                << remill::LLVMThingToString(decl.type);
    return llvm::UndefValue::get(decl_type);
  }
}


llvm::Value *LoadLiftedValue(const ValueDecl &decl, const TypeDictionary &types,
                             const remill::IntrinsicTable &intrinsics,
                             llvm::BasicBlock *in_block, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr) {

  llvm::IRBuilder ir(in_block);
  return LoadLiftedValue(decl, types, intrinsics, ir, state_ptr, mem_ptr);
}

namespace {

// Returns `true` if `reg_name` appears to be the name of the stack pointer
// register in the target architecture of `module`.
static bool IsStackPointerRegName(llvm::Module *module,
                                  const std::string &reg_name) {
  llvm::Triple triple(module->getTargetTriple());
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::x86: return reg_name == "esp";
    case llvm::Triple::ArchType::x86_64:
      return reg_name == "rsp" || reg_name == "esp";
    case llvm::Triple::ArchType::aarch64:
      return reg_name == "sp" || reg_name == "xsp" || reg_name == "wsp";
    case llvm::Triple::ArchType::aarch64_32:
    case llvm::Triple::ArchType::arm:
    case llvm::Triple::ArchType::armeb:
      return reg_name == "r13" || reg_name == "sp" || reg_name == "wsp";
    case llvm::Triple::ArchType::sparc:
    case llvm::Triple::ArchType::sparcel:
    case llvm::Triple::ArchType::sparcv9:
      return reg_name == "o6" || reg_name == "sp";
    default: return false;
  }
}

// Returns `true` if `reg_name` appears to be the name of the program counter
// register in the target architecture of `module`.
static bool IsProgramCounterRegName(llvm::Module *module,
                                    const std::string &reg_name) {
  llvm::Triple triple(module->getTargetTriple());
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::x86: return reg_name == "eip";
    case llvm::Triple::ArchType::x86_64:
      return reg_name == "rip" || reg_name == "eip";
    case llvm::Triple::ArchType::aarch64:
      return reg_name == "pc" || reg_name == "wpc";
    case llvm::Triple::ArchType::aarch64_32:
    case llvm::Triple::ArchType::arm:
    case llvm::Triple::ArchType::armeb: return reg_name == "pc";
    case llvm::Triple::ArchType::sparc:
    case llvm::Triple::ArchType::sparcel:
    case llvm::Triple::ArchType::sparcv9:
      return reg_name == "pc" || reg_name == "npc";
    default: return false;
  }
}

// Returns `true` if it looks like we're doing a load of something like
// `__anvill_reg_RSP`, which under certain lifting options, would represent
// an unmodelled dependency on the native stack pointer on entry to a function.
template <typename RegNamePred>
static bool IsLoadOfUnmodelledRegister(llvm::LoadInst *load, RegNamePred pred) {
  if (auto gv =
          llvm::dyn_cast<llvm::GlobalVariable>(load->getPointerOperand())) {
    if (const auto gv_name = gv->getName();
        gv_name.startswith(kUnmodelledRegisterPrefix)) {
      return pred(gv->getParent(),
                  gv_name.substr(kUnmodelledRegisterPrefix.size()).lower());
    }
  }
  return false;
}

// Returns `true` if it looks like we're calling a function that should get
// use the value of the native stack pointer on entry to a function.
//
// NOTE(pag): We're overly defensive here just in case parts of Anvill permit
//            using intrinsics in the future.
static bool IsCallRelatedToStackPointerItrinsic(llvm::CallBase *call) {
  const auto intrinsic_id = call->getIntrinsicID();

  // This is only valid on AArch64.
  if (intrinsic_id == llvm::Intrinsic::sponentry) {
    return true;

    // This intrinsic can be used for getting the address of the stack
    // pointer.
  } else if (intrinsic_id == llvm::Intrinsic::read_register) {
    auto reg_val = call->getArgOperand(0);
    auto reg_tuple_md = llvm::cast<llvm::MDTuple>(
        llvm::cast<llvm::MetadataAsValue>(reg_val)->getMetadata());
    auto reg_name_md = llvm::cast<llvm::MDString>(reg_tuple_md->getOperand(0));
    auto reg_name = reg_name_md->getString().lower();
    return IsStackPointerRegName(call->getModule(), reg_name);

  } else {
    return false;
  }
}

}  // namespace

class StackPointerResolverImpl {
 public:
  bool ResolveFromValue(llvm::Value *val);
  bool ResolveFromConstantExpr(llvm::ConstantExpr *ce);

  inline explicit StackPointerResolverImpl(llvm::Module *m) : module(m) {}

  llvm::Module *const module;
  std::unordered_map<llvm::Value *, bool> cache;
};

bool StackPointerResolverImpl::ResolveFromValue(llvm::Value *val) {

  // Lookup the cache and return the value if it exist
  auto it = cache.find(val);
  if (it != cache.end()) {
    return it->second;
  }

  auto &result = cache[val];
  if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    result = ResolveFromValue(pti->getOperand(0));
  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
    result = ResolveFromConstantExpr(ce);
  } else if (auto op2 = llvm::dyn_cast<llvm::BinaryOperator>(val)) {
    result = ResolveFromValue(op2->getOperand(0)) ||
             ResolveFromValue(op2->getOperand(1));
  } else if (auto op1 = llvm::dyn_cast<llvm::UnaryOperator>(val)) {
    result = ResolveFromValue(op1->getOperand(0));
  } else if (auto sel = llvm::dyn_cast<llvm::SelectInst>(val)) {
    result = ResolveFromValue(sel->getTrueValue()) ||
             ResolveFromValue(sel->getFalseValue());
  } else if (auto val2 = val->stripPointerCastsAndAliases();
             val2 && val2 != val) {
    result = ResolveFromValue(val2);
  } else {
    const auto &dl = module->getDataLayout();
    llvm::APInt ap(dl.getPointerSizeInBits(0), 0);
    if (auto val3 = val->stripAndAccumulateConstantOffsets(dl, ap, true);
        val3 && val3 != val) {
      result = ResolveFromValue(val3);
    } else {
      result = IsStackPointer(module, val);
    }
  }

  return result;
}

bool StackPointerResolverImpl::ResolveFromConstantExpr(llvm::ConstantExpr *ce) {
  if (ce->getOpcode()) {
    switch (ce->getOpcode()) {
      case llvm::Instruction::IntToPtr:
      case llvm::Instruction::PtrToInt:
      case llvm::Instruction::BitCast:
      case llvm::Instruction::AddrSpaceCast:
      case llvm::Instruction::GetElementPtr:
      case llvm::Instruction::Shl:
      case llvm::Instruction::LShr:
      case llvm::Instruction::AShr:
      case llvm::Instruction::UDiv:
      case llvm::Instruction::SDiv:
      case llvm::Instruction::Trunc:
      case llvm::Instruction::SExt:
      case llvm::Instruction::ZExt: return ResolveFromValue(ce->getOperand(0));
      case llvm::Instruction::Add:
      case llvm::Instruction::Sub:
      case llvm::Instruction::Mul:
      case llvm::Instruction::And:
      case llvm::Instruction::Or:
      case llvm::Instruction::Xor:
      case llvm::Instruction::ICmp:
        return ResolveFromValue(ce->getOperand(0)) ||
               ResolveFromValue(ce->getOperand(1));
      case llvm::Instruction::Select:
        return ResolveFromValue(ce->getOperand(0)) ||
               ResolveFromValue(ce->getOperand(1)) ||
               ResolveFromValue(ce->getOperand(2));
      case llvm::Instruction::FCmp:
        return ResolveFromValue(ce->getOperand(0)) ||
               ResolveFromValue(ce->getOperand(1)) ||
               ResolveFromValue(ce->getOperand(2));
      default: break;
    }
  }
  return false;
}

StackPointerResolver::~StackPointerResolver(void) {}
StackPointerResolver::StackPointerResolver(llvm::Module *module)
    : impl(new StackPointerResolverImpl(module)) {}

// Returns `true` if it looks like `val` is derived from a symbolic stack
// pointer representation.
bool StackPointerResolver::IsRelatedToStackPointer(llvm::Value *val) const {
  return impl->ResolveFromValue(val);
}

bool IsRelatedToStackPointer(llvm::Module *module, llvm::Value *val) {
  StackPointerResolverImpl impl(module);
  return impl.ResolveFromValue(val);
}

// Returns `true` if it looks like `val` is the stack counter.
bool IsStackPointer(llvm::Module *module, llvm::Value *val) {
  if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    return gv->getName() == kSymbolicSPName;

  } else if (auto load = llvm::dyn_cast<llvm::LoadInst>(val)) {
    return IsLoadOfUnmodelledRegister(load, IsStackPointerRegName);

  } else if (auto call = llvm::dyn_cast<llvm::CallBase>(val)) {
    return IsCallRelatedToStackPointerItrinsic(call);

  } else {
    return false;
  }
}

// Returns `true` if it looks like `val` is the program counter.
bool IsProgramCounter(llvm::Module *, llvm::Value *val) {
  if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    return gv->getName() == kSymbolicPCName;

  } else if (auto load = llvm::dyn_cast<llvm::LoadInst>(val)) {
    return IsLoadOfUnmodelledRegister(load, IsProgramCounterRegName);

    // TODO(pag): Cover arguments to remill three-argument form functions?
  } else {
    return false;
  }
}

static bool IsAcceptableReturnAddressDisplacement(llvm::Module *module,
                                                  llvm::Constant *v) {
  auto ci = llvm::dyn_cast<llvm::ConstantInt>(v);
  if (!ci) {
    return false;
  }

  auto disp = ci->getZExtValue();

  llvm::Triple triple(module->getTargetTriple());
  switch (triple.getArch()) {
    case llvm::Triple::ArchType::sparc:
    case llvm::Triple::ArchType::sparcel:
    case llvm::Triple::ArchType::sparcv9:
      return disp == 0u || disp == 4u || disp == 8u;
    default: return disp == 0;
  }
}

// Returns `true` if it looks like `val` is the return address.
bool IsReturnAddress(llvm::Module *module, llvm::Value *val) {
  const auto addressofreturnaddress = [](llvm::CallBase *call) -> bool {
    return call &&
           call->getIntrinsicID() == llvm::Intrinsic::addressofreturnaddress;
  };

  if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    return gv->getName() == kSymbolicRAName;

  } else if (auto call = llvm::dyn_cast<llvm::CallBase>(val)) {
    if (call->getIntrinsicID() == llvm::Intrinsic::returnaddress ||
        call->getIntrinsicID() == llvm::Intrinsic::sponentry) {
      return true;
    } else if (auto func = call->getCalledFunction();
               func && func->getName().startswith("__remill_read_memory_")) {
      return addressofreturnaddress(
          llvm::dyn_cast<llvm::CallBase>(call->getArgOperand(1)));
    } else {
      return false;
    }
  } else if (auto li = llvm::dyn_cast<llvm::LoadInst>(val)) {
    return addressofreturnaddress(
        llvm::dyn_cast<llvm::CallBase>(li->getPointerOperand()));

  } else if (auto pti = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return IsReturnAddress(module, pti->getOperand(0));

  } else if (auto itp = llvm::dyn_cast<llvm::IntToPtrInst>(val)) {
    return IsReturnAddress(module, itp->getOperand(0));

  } else if (auto bc = llvm::dyn_cast<llvm::BitCastOperator>(val)) {
    return IsReturnAddress(module, bc->getOperand(0));

  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
    switch (ce->getOpcode()) {
      case llvm::Instruction::Add: {
        llvm::Constant *o0 = ce->getOperand(0);
        llvm::Constant *o1 = ce->getOperand(1);
        if (IsReturnAddress(module, o0)) {
          return IsAcceptableReturnAddressDisplacement(module, o1);
        } else if (IsReturnAddress(module, o1)) {
          return IsAcceptableReturnAddressDisplacement(module, o0);

        } else {
          return false;
        }
      }

      case llvm::Instruction::IntToPtr:
        return IsReturnAddress(module, ce->getOperand(0));

      default: return false;
    }

  } else {
    return false;
  }
}

// Returns `true` if `val` looks like it is backed by a definition, and thus can
// be the aliasee of an `llvm::GlobalAlias`.
bool CanBeAliased(llvm::Value *val) {
  if (!val) {
    return false;
  } else if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(val)) {
    return !gv->isDeclaration();
  } else if (auto f = llvm::dyn_cast<llvm::Function>(val)) {
    return !f->isDeclaration();
  } else if (auto ga = llvm::dyn_cast<llvm::GlobalAlias>(val)) {
    return CanBeAliased(ga->getAliasee());
  } else if (auto gep = llvm::dyn_cast<llvm::GEPOperator>(val)) {
    return CanBeAliased(gep->getPointerOperand());
  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(val)) {
    switch (ce->getOpcode()) {
      case llvm::Instruction::BitCast:
      case llvm::Instruction::PtrToInt:
      case llvm::Instruction::IntToPtr: return CanBeAliased(ce->getOperand(0));
      default: return false;
    }
  } else {
    return false;
  }
}

std::optional<uint64_t> GetBasicBlockAddr(llvm::Function *func) {
  auto meta = func->getMetadata(kBasicBlockMetadata);
  if (!meta) {
    return std::nullopt;
  }

  auto v = llvm::cast<llvm::ValueAsMetadata>(meta->getOperand(0))->getValue();

  return llvm::cast<llvm::ConstantInt>(v)->getLimitedValue();
}

}  // namespace anvill
