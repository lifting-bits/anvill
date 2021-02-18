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

#include "anvill/Analyze.h"

#include <glog/logging.h>
#include <remill/BC/Compat/GlobalValue.h>

// clang-format off
#include <remill/BC/Compat/CTypes.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/Utils/Local.h>

// clang-format on

#include <remill/BC/Compat/ScalarTransforms.h>
#include <remill/BC/Optimizer.h>
#include <remill/BC/Util.h>

#include <map>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "anvill/Decl.h"
#include "anvill/Program.h"
#include "anvill/Util.h"

namespace anvill {

XrefExprFolder::XrefExprFolder(const Program &program_, llvm::Module &module_)
    : program(program_),
      module(module_),
      error(llvm::Error::success()) {}

void XrefExprFolder::Reset(void) {
  is_ci_relative = false;
  is_pc_relative = false;
  is_sp_relative = false;
  is_ra_relative = false;
  is_gv_relative = false;
  is_pointer = false;
  left_shift_amount = 0;
  right_shift_amount = 0;
  bits_xor = 0;
  bits_and = 0;
  hinted_type = nullptr;

  // Drop the error.
  llvm::handleAllErrors(std::move(error), [](llvm::ErrorInfoBase &) {});
}

uint64_t XrefExprFolder::Visit(llvm::Value *v) {
  if (auto c = llvm::dyn_cast<llvm::Constant>(v); c) {
    return VisitConst(c);

  } else if (auto i = llvm::dyn_cast<llvm::Instruction>(v); i) {
    return VisitInst(i);

  } else {
    auto err = llvm::createStringError(std::errc::address_not_available,
                                       "Could not fold value");
    if (error) {
      error = llvm::joinErrors(std::move(error), std::move(err));
    } else {
      error = std::move(err);
    }
    return 0;
  }
}

uint64_t XrefExprFolder::VisitInst(llvm::Instruction *ce) {
  if (error) {
    return 0;
  }

  switch (ce->getOpcode()) {
    case llvm::Instruction::GetElementPtr: return VisitGEP(ce);
    case llvm::Instruction::Add:
      return VisitAdd(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::Sub:
      return VisitSub(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::Mul:
      return VisitMul(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::And:
      return VisitAnd(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::Or:
      return VisitOr(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::Xor:
      return VisitXor(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::ICmp: return VisitICmp(ce);
    case llvm::Instruction::ZExt:
      return VisitZExt(ce->getOperand(0), ce->getType());
    case llvm::Instruction::SExt:
      return VisitSExt(ce->getOperand(0), ce->getType());
    case llvm::Instruction::Trunc:
      return VisitTrunc(ce->getOperand(0), ce->getType());
    case llvm::Instruction::Select:
      return VisitSelect(ce->getOperand(0), ce->getOperand(1),
                         ce->getOperand(2));
    case llvm::Instruction::Shl:
      return VisitShl(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::LShr:
      return VisitLShr(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::AShr:
      return VisitAShr(ce->getOperand(0), ce->getOperand(1));
    case llvm::Instruction::IntToPtr:
    case llvm::Instruction::PtrToInt:
    case llvm::Instruction::BitCast: return Visit(ce->getOperand(0));
    case llvm::Instruction::Call:
      return VisitCall(llvm::dyn_cast<llvm::CallInst>(ce));
    default: break;
  }

  error = llvm::createStringError(std::errc::address_not_available,
                                  "Could not fold instruction: %s",
                                  remill::LLVMThingToString(ce).c_str());
  return 0;
}

uint64_t XrefExprFolder::VisitConst(llvm::Constant *c) {
  if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(c); gv) {
    if (gv->getName() == "__anvill_pc") {
      is_pc_relative = true;
      is_pointer = true;
      return 0;

    } else if (gv->getName() == "__anvill_sp") {
      is_sp_relative = true;
      is_pointer = true;
      return 0;

    } else if (gv->getName() == "__anvill_ra") {
      is_ra_relative = true;
      is_pointer = true;
      return 0;

    } else if (gv->getName() == "__anvill_ci") {
      is_ci_relative = true;
      return 0;
    } else if (gv->getName().startswith("__anvill_type")) {
      is_pointer = true;
      hinted_type = remill::GetValueType(gv);
      return 0;
    } else if (auto [resolved, ea] = TryResolveGlobal(gv); resolved) {
      is_gv_relative = true;
      is_pointer = true;
      return ea;

    } else {
      auto err = llvm::createStringError(
          std::errc::address_not_available,
          "Could not resolve address of global variable: %s",
          gv->getName().str().c_str());
      if (error) {
        error = llvm::joinErrors(std::move(error), std::move(err));
      } else {
        error = std::move(err);
      }
      return 0;
    }
  } else if (auto alias = llvm::dyn_cast<llvm::GlobalAlias>(c); alias) {
    return VisitConst(alias->getAliasee());

  } else if (auto func = llvm::dyn_cast<llvm::Function>(c); func) {
    if (auto [resolved, ea] = TryResolveGlobal(func); resolved) {
      is_pc_relative = true;
      return ea;

    } else {
      if (error) {
        auto err = llvm::createStringError(
            std::errc::address_not_available,
            "; Could not resolve address of function: %s",
            func->getName().str().c_str());
        error = llvm::joinErrors(std::move(error), std::move(err));
      } else {
        auto err =
            llvm::createStringError(std::errc::address_not_available,
                                    "Could not resolve address of function: %s",
                                    func->getName().str().c_str());
        error = std::move(err);
      }
      return 0;
    }
  } else if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(c); ci) {
    return ci->getZExtValue();

  } else if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(c); ce) {
    switch (ce->getOpcode()) {
      case llvm::Instruction::GetElementPtr: return VisitGEP(ce);
      case llvm::Instruction::Add:
        return VisitAdd(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::Sub:
        return VisitSub(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::Mul:
        return VisitMul(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::And:
        return VisitAnd(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::Or:
        return VisitOr(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::Xor:
        return VisitXor(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::ICmp: return VisitICmp(ce);
      case llvm::Instruction::ZExt:
        return VisitZExt(ce->getOperand(0), ce->getType());
      case llvm::Instruction::SExt:
        return VisitSExt(ce->getOperand(0), ce->getType());
      case llvm::Instruction::Trunc:
        return VisitTrunc(ce->getOperand(0), ce->getType());
      case llvm::Instruction::Select:
        return VisitSelect(ce->getOperand(0), ce->getOperand(1),
                           ce->getOperand(2));
      case llvm::Instruction::Shl:
        return VisitShl(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::LShr:
        return VisitLShr(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::AShr:
        return VisitAShr(ce->getOperand(0), ce->getOperand(1));
      case llvm::Instruction::IntToPtr:
      case llvm::Instruction::PtrToInt:
      case llvm::Instruction::BitCast: return VisitConst(ce->getOperand(0));
      default: break;
    }
  }

  auto err = llvm::createStringError(std::errc::address_not_available,
                                     "Could not fold constant expression: %s",
                                     remill::LLVMThingToString(c).c_str());
  if (error) {
    error = llvm::joinErrors(std::move(error), std::move(err));
  } else {
    error = std::move(err);
  }
  return 0;
}

uint64_t XrefExprFolder::VisitGEP(llvm::Value *val) {
  const auto &dl = module.getDataLayout();
  auto gep = llvm::dyn_cast<llvm::GEPOperator>(val);
  llvm::APInt ap(dl.getPointerSizeInBits(0), Visit(gep->getPointerOperand()));
  if (gep->accumulateConstantOffset(dl, ap)) {
    return ap.getZExtValue();
  } else {
    auto err =
        llvm::createStringError(std::errc::address_not_available,
                                "Non-constant getelementptr index sequence");
    if (error) {
      error = llvm::joinErrors(std::move(error), std::move(err));
    } else {
      error = std::move(err);
    }
    return 0;
  }
}

uint64_t XrefExprFolder::VisitAdd(llvm::Value *lhs, llvm::Value *rhs) {
  const uint64_t size = lhs->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Visit(lhs);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = Visit(rhs);
  is_pointer = is_pointer ^ is_pointer_copy;
  return (lhs_val + rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitMul(llvm::Value *lhs, llvm::Value *rhs) {
  const uint64_t size = lhs->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Visit(lhs);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = Visit(rhs);
  is_pointer = is_pointer ^ is_pointer_copy;
  return (lhs_val * rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitSub(llvm::Value *lhs, llvm::Value *rhs) {
  const auto type = llvm::dyn_cast<llvm::IntegerType>(lhs->getType());
  const uint64_t size = type->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Visit(lhs);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = Visit(rhs);
  is_pointer = is_pointer_copy;
  return (lhs_val - rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitAnd(llvm::Value *lhs, llvm::Value *rhs) {
  const uint64_t size = lhs->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Visit(lhs);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = Visit(rhs);
  is_pointer = is_pointer ^ is_pointer_copy;
  if (llvm::isa<llvm::ConstantInt>(lhs)) {
    bits_and |= lhs_val;
  }
  if (llvm::isa<llvm::ConstantInt>(rhs)) {
    bits_and |= rhs_val;
  }
  return (lhs_val & rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitOr(llvm::Value *lhs, llvm::Value *rhs) {
  const uint64_t size = lhs->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Visit(lhs);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = Visit(rhs);
  is_pointer = is_pointer ^ is_pointer_copy;
  return (lhs_val | rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitXor(llvm::Value *lhs, llvm::Value *rhs) {
  const uint64_t size = lhs->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Visit(lhs);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = Visit(rhs);
  if (llvm::isa<llvm::ConstantInt>(lhs)) {
    bits_xor |= (lhs_val ? lhs_val : ~lhs_val);
  }
  if (llvm::isa<llvm::ConstantInt>(rhs)) {
    bits_xor |= (rhs_val ? rhs_val : ~rhs_val);
  }
  is_pointer = is_pointer ^ is_pointer_copy;
  return (lhs_val ^ rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitShl(llvm::Value *lhs, llvm::Value *rhs) {
  const uint64_t size = lhs->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Visit(lhs);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = Visit(rhs);
  if (llvm::isa<llvm::ConstantInt>(rhs)) {
    left_shift_amount += static_cast<unsigned>(rhs_val);
  }
  is_pointer = is_pointer_copy;
  return (lhs_val << rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitLShr(llvm::Value *lhs, llvm::Value *rhs) {
  const uint64_t size = lhs->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Visit(lhs);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = Visit(rhs);
  if (llvm::isa<llvm::ConstantInt>(rhs)) {
    right_shift_amount += static_cast<unsigned>(rhs_val);
  }
  is_pointer = is_pointer_copy;
  return (lhs_val >> rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitAShr(llvm::Value *lhs_op, llvm::Value *rhs_op) {
  const uint64_t size = lhs_op->getType()->getPrimitiveSizeInBits();
  const uint64_t mask = size < 64 ? (1ull << size) - 1ull : ~0ull;
  const auto lhs_val = Signed(Visit(lhs_op), lhs_op);
  const auto is_pointer_copy = is_pointer;
  const auto rhs_val = static_cast<int64_t>(Visit(rhs_op));
  if (llvm::isa<llvm::ConstantInt>(rhs_op)) {
    right_shift_amount += static_cast<unsigned>(rhs_val);
  }
  is_pointer = is_pointer_copy;
  return static_cast<uint64_t>(lhs_val >> rhs_val) & mask;
}

uint64_t XrefExprFolder::VisitCall(llvm::CallInst *call) {
  auto id = call->getIntrinsicID();
  switch (id) {
    case llvm::Intrinsic::ctpop: {
      auto val = Visit(call->getArgOperand(0));
      return __builtin_popcountl(val);
    }
    default: break;
  }
  // This will happen like all the time, its sorta an error, sorta a warning, it doesnt really matter
  auto err = llvm::createStringError(std::errc::address_not_available,
                                     "Unrecognized call instruction");
  if (error) {
    error = llvm::joinErrors(std::move(error), std::move(err));
  } else {
    error = std::move(err);
  }
  return 0;
}

int64_t XrefExprFolder::Signed(uint64_t val, llvm::Value *op) {
  switch (const uint64_t size = op->getType()->getPrimitiveSizeInBits(); size) {
    case 1:
      if (val & 1) {
        return -1;
      } else {
        return 0;
      }
    case 8: return static_cast<int8_t>(val);
    case 16: return static_cast<int16_t>(val);
    case 32: return static_cast<int8_t>(val);
    case 64: return static_cast<int64_t>(val);
    default:
      CHECK_LT(size, 64u);
      const uint64_t m = 1ull << (size - 1ull);
      return static_cast<int64_t>(((val ^ m) - m));
  }
}

uint64_t XrefExprFolder::VisitICmp(llvm::Instruction *inst) {
  const auto icmp = llvm::dyn_cast<llvm::ICmpInst>(inst);
  return VisitICmp(icmp->getPredicate(), icmp->getOperand(0),
                   icmp->getOperand(1));
}

uint64_t XrefExprFolder::VisitICmp(llvm::ConstantExpr *ce) {
  return VisitICmp(ce->getPredicate(), ce->getOperand(0), ce->getOperand(1));
}

uint64_t XrefExprFolder::VisitICmp(unsigned pred, llvm::Value *lhs_op,
                                   llvm::Value *rhs_op) {
  const uint64_t lhs = Visit(lhs_op);
  const uint64_t rhs = Visit(rhs_op);
  Reset();
  switch (pred) {
    case llvm::CmpInst::ICMP_EQ: return lhs == rhs;
    case llvm::CmpInst::ICMP_NE: return lhs != rhs;
    case llvm::CmpInst::ICMP_UGT: return lhs > rhs;
    case llvm::CmpInst::ICMP_UGE: return lhs >= rhs;
    case llvm::CmpInst::ICMP_ULT: return lhs < rhs;
    case llvm::CmpInst::ICMP_ULE: return lhs <= rhs;
    case llvm::CmpInst::ICMP_SGT:
      return Signed(lhs, lhs_op) > Signed(rhs, rhs_op);
    case llvm::CmpInst::ICMP_SGE:
      return Signed(lhs, lhs_op) >= Signed(rhs, rhs_op);
    case llvm::CmpInst::ICMP_SLT:
      return Signed(lhs, lhs_op) < Signed(rhs, rhs_op);
    case llvm::CmpInst::ICMP_SLE:
      return Signed(lhs, lhs_op) <= Signed(rhs, rhs_op);
    default: {
      auto err = llvm::createStringError(
          std::errc::address_not_available,
          "Unsupported predicate in expression: %u", pred);
      if (error) {
        error = llvm::joinErrors(std::move(error), std::move(err));
      } else {
        error = std::move(err);
      }
      return 0;
    }
  }
}

uint64_t XrefExprFolder::VisitSelect(llvm::Value *cond, llvm::Value *if_true,
                                     llvm::Value *if_false) {
  const auto sel = Visit(cond);
  if (error) {
    return 0;
  }
  Reset();
  if (sel) {
    return Visit(if_true);
  } else {
    return Visit(if_false);
  }
}

uint64_t XrefExprFolder::VisitZExt(llvm::Value *op, llvm::Type *type) {
  auto ea = Visit(op);
  const uint64_t src_size = type->getPrimitiveSizeInBits();
  if (src_size >= 64u) {
    return ea;
  } else {
    const auto mask = (1ull << src_size) - 1ull;
    return (ea & mask);
  }
}

uint64_t XrefExprFolder::VisitSExt(llvm::Value *op, llvm::Type *type) {
  auto ea = Visit(op);
  const auto src_size = op->getType()->getPrimitiveSizeInBits();
  const auto dest_size = type->getPrimitiveSizeInBits();
  CHECK_LT(src_size, 64u);
  CHECK_LE(dest_size, 64u);
  const uint64_t m = 1ull << (src_size - 1ull);
  const uint64_t x = ea & ((1ull << dest_size) - 1ull);
  return ((x ^ m) - m);
}

uint64_t XrefExprFolder::VisitTrunc(llvm::Value *op, llvm::Type *type) {
  auto ea = Visit(op);
  const auto dest_size = type->getPrimitiveSizeInBits();

  // return ea if dest type is not trucated
  if (dest_size == 64u) {
    return ea;
  }

  CHECK_LE(dest_size, 64u);
  const auto mask = (1ull << dest_size) - 1ull;
  return (ea & mask);
}

std::pair<bool, uint64_t>
XrefExprFolder::TryResolveGlobal(llvm::GlobalValue *gv) {
  std::pair<bool, uint64_t> ret = {false, 0};

  program.ForEachAddressOfName(
      gv->getName().str(),
      [&ret](uint64_t ea, const FunctionDecl *, const GlobalVarDecl *) {
        ret.first = true;
        ret.second = ea;
        return false;
      });

  return ret;
}

namespace {

struct Cell {
  llvm::Type *type{nullptr};
  llvm::Use *use{nullptr};
  uint64_t address_const{0};
  unsigned size{0};
  bool is_load{false};
  bool is_store{false};
  bool is_volatile{false};
  bool is_atomic{false};
};

// Get the type that `val` ends up being converted to.
//
// NOTE(pag): `val` in an integer or floating point type.
static llvm::Type *GetDownstreamType(llvm::Value *val) {
  for (auto &use : val->uses()) {
    auto down_val = use.get();
    if (llvm::isa<llvm::BitCastOperator>(down_val) ||
        llvm::isa<llvm::IntToPtrInst>(down_val)) {
      return GetDownstreamType(down_val);
    }
  }
  return val->getType();
}

// Get the type that is the source of `val`.
//
// NOTE(pag): `val` is an integer or float type.
static llvm::Type *GetUpstreamType(llvm::Value *val) {
  if (auto bc_inst = llvm::dyn_cast<llvm::BitCastOperator>(val)) {
    return GetUpstreamType(bc_inst->getOperand(0));

  } else if (auto ptr_inst = llvm::dyn_cast<llvm::PtrToIntOperator>(val)) {
    return ptr_inst->getOperand(0)->getType();

  } else {
    return val->getType();
  }
}

// Get the type that is the source of `val`.
//
// NOTE(pag): `val` is a pointer type.
static llvm::Type *GetUpstreamTypeFromPointer(llvm::Value *val) {
  auto stripped = val->stripPointerCasts();
  return GetDownstreamType(stripped);
}

static bool ClassifyCell(const llvm::DataLayout &dl, Cell &cell) {
  const auto user = cell.use->getUser();

  if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user); call_inst) {

    llvm::StringRef name;
    const auto intrinsic = call_inst->getCalledFunction();
    if (intrinsic) {
      auto callee_name = intrinsic->getName();
      if (callee_name.startswith("__remill")) {
        name = callee_name;
      }
    }

    // Loads.
    if (name.startswith("__remill_read_memory_")) {
      cell.is_load = true;
      cell.type = GetDownstreamType(call_inst);

    // Stores.
    } else if (name.startswith("__remill_write_memory_")) {
      cell.is_store = true;
      cell.type = GetUpstreamType(call_inst->getArgOperand(2));

    // Compare-and-swap.
    } else if (name.startswith("__remill_compare_exchange_")) {
      cell.is_load = true;
      cell.is_store = true;
      cell.is_atomic = true;
      cell.type = GetUpstreamType(call_inst->getArgOperand(3));

    // Fetch-and-update.
    } else if (name.startswith("__remill_fetch_and_")) {
      cell.is_load = true;
      cell.is_store = true;
      cell.is_atomic = true;
      cell.type = GetUpstreamTypeFromPointer(call_inst->getArgOperand(2));

    // Loads from memory mapped I/O.
    } else if (name.startswith("__remill_read_io_port_")) {
      cell.is_load = true;
      cell.is_volatile = true;
      cell.type = GetDownstreamType(call_inst);

    // Stores to memory mapped I/O.
    } else if (name.startswith("__remill_write_io_port_")) {
      cell.is_store = true;
      cell.is_volatile = true;
      cell.type = GetUpstreamType(call_inst->getArgOperand(2));
    }

  } else if (llvm::isa<llvm::BitCastOperator>(user) ||
             llvm::isa<llvm::PtrToIntOperator>(user) ||
             llvm::isa<llvm::IntToPtrInst>(user)) {
    cell.type = GetDownstreamType(user);

  } else if (llvm::isa<llvm::BinaryOperator>(user)) {
    cell.type = user->getType();
  }

  if (!cell.type) {
    cell.type = cell.use->get()->getType();
  }

  if (cell.type->isFunctionTy()) {
    cell.size = dl.getPointerSize(0);
    return true;

  } else if (cell.type->isSized(nullptr)) {
    cell.size = static_cast<unsigned>(dl.getTypeAllocSize(cell.type));
    return true;

  } else {
    return false;
  }
}

static void FindPossibleCrossReferences(
    const Program &program, llvm::Module &module, llvm::StringRef gv_name,
    std::vector<std::tuple<llvm::Use *, Byte, llvm::Type *>> &ptr_fixups,
    std::vector<std::tuple<llvm::Use *, Byte, llvm::Type *>> &maybe_fixups,
    std::vector<std::tuple<llvm::Use *, uint64_t, llvm::Type *>> &imm_fixups) {

  std::vector<std::tuple<llvm::Use *, llvm::Value *, bool>> work_list;
  std::vector<std::tuple<llvm::Use *, llvm::Value *, bool>> next_work_list;

  if (auto gv = module.getGlobalVariable(gv_name); gv) {
    for (auto &use : gv->uses()) {
      next_work_list.emplace_back(&use, gv, true);
    }
  } else {
    return;
  }

  XrefExprFolder folder(program, module);
  std::unordered_set<llvm::Use *> seen;

  while (!next_work_list.empty()) {

    next_work_list.swap(work_list);
    next_work_list.clear();

    for (auto [use_, val_, report_failure_] : work_list) {
      llvm::Use *const use = use_;
      llvm::Value *const val = val_;
      const bool report_failure = report_failure_;

      if (seen.count(use)) {
        continue;
      }
      seen.insert(use);

      folder.Reset();
      const auto ea = folder.Visit(val);
      if (folder.error) {
        LOG_IF(ERROR, folder.hinted_type != nullptr)
            << remill::LLVMThingToString(folder.hinted_type);
        llvm::handleAllErrors(
            std::move(folder.error), [=](llvm::ErrorInfoBase &eib) {
              LOG_IF(ERROR, report_failure)
                  << "Unable to handle possible cross-reference to " << std::hex
                  << ea << std::dec << ": " << eib.message();
            });
        continue;
      }
      auto type = folder.hinted_type;
      if (auto byte = program.FindByte(ea);
          byte && !folder.is_sp_relative && !folder.is_ra_relative) {
        if (folder.is_pointer) {
          ptr_fixups.emplace_back(use, byte, type);
        } else {
          maybe_fixups.emplace_back(use, byte, type);
        }
      } else if (type && folder.is_pointer) {
        ptr_fixups.emplace_back(use, anvill::Byte(), type);
      } else {
        imm_fixups.emplace_back(use, ea, type);
      }

      // Recursively ascend the usage graph.
      const auto user = use->getUser();
      for (auto &use_of_val : user->uses()) {
        next_work_list.emplace_back(&use_of_val, user, false);
      }
    }
  }

  folder.Reset();
}

static constexpr uint64_t kStackBias = 4096 * 3;

struct StackFrame {
 public:
  std::vector<Cell> cells;

  // NOTE(pag): This is based off of the amd64 ABI redzone, and
  //            hopefully represents an appropriate redzone size.
  //
  //            Consider having additional info in the `FunctionDecl`
  //            for either frame size or redzone size.
  uint64_t min_ea{kStackBias - 128};

  uint64_t max_ea{kStackBias};
};

static void RecoverStackMemoryAccesses(
    const std::vector<std::tuple<llvm::Use *, uint64_t, llvm::Type *>>
        &sp_fixups,
    llvm::Module &module) {

  std::unordered_map<llvm::Function *, StackFrame> frames;

  auto &context = module.getContext();
  const auto &dl = module.getDataLayout();
  const auto ptr_size = dl.getPointerSizeInBits(0);
  const auto i8_type = llvm::Type::getInt8Ty(context);

  for (auto [use, ea, type] : sp_fixups) {
    llvm::Instruction *inst = llvm::dyn_cast<llvm::Instruction>(use->getUser());
    if (!inst) {
      LOG(WARNING) << "Ignoring non-inst user: "
                   << remill::LLVMThingToString(use->getUser());
      continue;
    }

    auto func = inst->getFunction();
    auto &frame = frames[func];
    auto &cell = frame.cells.emplace_back();

    if (32 == ptr_size) {
      cell.address_const =
          static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(ea)) +
                                static_cast<int64_t>(kStackBias));
    } else {
      cell.address_const = static_cast<uint64_t>(
          static_cast<int64_t>(ea) + static_cast<int64_t>(kStackBias));
    }

    cell.use = use;
    if (!ClassifyCell(dl, cell)) {
      cell.type = i8_type;
      cell.size = 1;
    }

    frame.min_ea = std::min(frame.min_ea, cell.address_const);
    frame.max_ea = std::max(frame.max_ea, cell.address_const + cell.size);
  }

  // Order cells to prefer wider types over smaller types, or wider aligned
  // types over lesser aligned types.
  auto order_cells = [&dl](const Cell &a, const Cell &b) -> bool {
    if (a.address_const < b.address_const) {
      return true;
    } else if (a.address_const > b.address_const) {
      return false;
    } else if (a.size == b.size) {
      if (a.type == b.type) {
        return false;
      } else {

        // If one of the types is a pointer type, then make it ordered first.
        // We give preference to pointer types when possible so that we have
        // fewer integer-to-pointer casts later on.
        const auto a_is_ptr = a.type->isPointerTy();
        const auto b_is_ptr = b.type->isPointerTy();
        if (a_is_ptr != b_is_ptr) {
          return a_is_ptr;
        }

        auto a_align = dl.getABITypeAlignment(a.type);
        auto b_align = dl.getABITypeAlignment(b.type);
        if (a_align == b_align) {
          return a.type < b.type;
        } else {
          return a_align > b_align;
        }
      }
    } else {
      return a.size > b.size;
    }
  };

  // Types within the stack frame for a given function.
  std::vector<llvm::Type *> types;

  for (auto &[func, frame_] : frames) {
    StackFrame &frame = frame_;

    // Sort the cells, grouped by bytes, ordering larger cells
    std::sort(frame.cells.begin(), frame.cells.end(), order_cells);

    auto last_size = dl.getPointerSize(0);
    llvm::Type *last_type =
        llvm::IntegerType::get(context, dl.getPointerSizeInBits(0));

    auto fill_up_to = [=, &types](uint64_t running_addr, uint64_t ea) {
      while (last_size && (running_addr + last_size) <= ea) {
        types.push_back(last_type);
        running_addr += last_size;
      }
      for (; running_addr < ea; running_addr += 1) {
        types.push_back(i8_type);
      }
      return running_addr;
    };

    types.clear();

    // Build up the sequence of types into `type` that will make up the stack
    // frame structure.
    auto running_addr = frame.min_ea;
    for (const auto &cell : frame.cells) {
      if (running_addr > cell.address_const) {
        continue;
      } else {
        running_addr = fill_up_to(running_addr, cell.address_const);
        types.push_back(cell.type);
        running_addr += cell.size;
        last_size = cell.size;
        last_type = cell.type;
      }
    }

    if (running_addr < frame.max_ea) {
      (void) fill_up_to(running_addr, frame.max_ea);
    }

    llvm::IRBuilder<> ir(&(func->getEntryBlock().front()));
    std::stringstream frame_ss;
    const auto frame_type = llvm::StructType::create(
        context, types, func->getName().str() + ".frame_type", true);
    const auto frame_ptr = ir.CreateAlloca(frame_type);

    std::unordered_map<uint64_t, llvm::Value *> offset_cache;

    for (const auto &cell : frame.cells) {
      auto &gep = offset_cache[cell.address_const];
      if (!gep) {
        const auto goal_offset = cell.address_const - frame.min_ea;

        // NOTE(surovic):
        // This thing iteratively builds up a GEP to point to an offset.
        // It moves in increments that are as wide as an element of the
        // indexed type. However if there's some leftover offset, it tries
        // to do some casting magic to satisfy the request. The assumption
        // is that the leftover is smaller than the size of a single element
        // which doesn't hold for tests/binja_none_type.
        gep = remill::BuildPointerToOffset(
            ir, frame_ptr, goal_offset, llvm::PointerType::get(cell.type, 0));
      }

      auto dest_type = cell.use->get()->getType();
      if (dest_type->isIntegerTy()) {
        gep = ir.CreatePtrToInt(gep, dest_type);
      } else if (dest_type->isPointerTy()) {
        gep = ir.CreateBitCast(gep, dest_type);
      }
      cell.use->set(gep);
    }
  }
}

void RecoverMemoryAccesses(
    const Program &program, llvm::Module &module,
    const std::vector<std::tuple<llvm::Use *, Byte, llvm::Type *>> &fixups) {
  for (auto [use, byte, type] : fixups) {
    const auto user = llvm::dyn_cast<llvm::Instruction>(use->getUser());
    if (!user) {
      continue;  // We're not allowed to replace uses inside of constants.
    }

    CHECK(!llvm::isa<llvm::ConstantExpr>(use->getUser()));

    const auto addr = byte.Address();
    const auto used_val = use->get();
    const auto used_type = used_val->getType();
    const auto int_type = llvm::dyn_cast<llvm::IntegerType>(used_type);
    if (!int_type) {
      LOG(ERROR) << "Unexpected type of value "
                 << remill::LLVMThingToString(used_val) << " by "
                 << remill::LLVMThingToString(user);
      continue;
    }

    llvm::IRBuilder<> builder(user->getParent());
    builder.SetInsertPoint(user);
    auto ptr_type = llvm::dyn_cast_or_null<llvm::PointerType>(type);
    if (!ptr_type) {
      ptr_type = llvm::Type::getInt8PtrTy(module.getContext(), 0);
    }
    llvm::Value *new_val = GetAddress(program, module, addr, builder, ptr_type);

    // TODO(pag): Leaving these as integers might be best, as we may go an
    //            collect them in the optimizer.
    if (!new_val) {
      if (addr) {
        LOG(ERROR) << "TODO: Found byte address " << std::hex << addr
                   << std::dec
                   << " that is mapped to memory but doesn't directly "
                   << "resolve to a function or variable";
        new_val = llvm::ConstantInt::get(int_type, addr, false);
      } else {
        new_val = used_val;
      }
    }
    if (new_val != used_val) {
      use->set(new_val);
    }
  }
}

void ReplaceImmediateIntegers(
    const Program &program,
    const std::vector<std::tuple<llvm::Use *, uint64_t, llvm::Type *>>
        &ci_fixups) {
  for (auto [use, imm_val, type] : ci_fixups) {
    const auto user = llvm::dyn_cast<llvm::Instruction>(use->getUser());
    if (!user) {
      continue;  // We're not allowed to replace uses inside of constants.
    }

    const auto used_val = use->get();
    const auto used_type = used_val->getType();
    const auto int_type = llvm::dyn_cast<llvm::IntegerType>(used_type);
    if (!int_type) {
      LOG(ERROR) << "Unexpected type of value "
                 << remill::LLVMThingToString(used_val) << " by "
                 << remill::LLVMThingToString(
                        llvm::dyn_cast<llvm::Value>(use->getUser()));
      continue;
    }

    const auto new_val = llvm::ConstantInt::get(int_type, imm_val, false);
    if (new_val != used_val) {
      use->set(new_val);
    }
  }
}

// Convert uses of `__anvill_ra` into uses of the return address intrinsics.
static void RecoverReturnAddressUses(
    llvm::Module &module,
    const std::vector<std::tuple<llvm::Use *, uint64_t, llvm::Type *>>
        &fixups) {
  for (auto [use, val, type] : fixups) {
    (void) val;
    if (auto user = llvm::dyn_cast<llvm::Instruction>(use->getUser()); user) {
      UnfoldConstantExpressions(user);
    }
  }

  std::unordered_map<llvm::Function *, std::vector<llvm::Use *>> uses_by_func;
  if (auto ra = module.getGlobalVariable("__anvill_ra"); ra) {
    for (auto &use : ra->uses()) {
      if (auto user = llvm::dyn_cast<llvm::Instruction>(use.getUser()); user) {
        auto block = user->getParent();
        auto func = block->getParent();
        uses_by_func[func].push_back(&use);
      }
    }
  }

  auto &context = module.getContext();
  auto i32_ty = llvm::Type::getInt32Ty(context);
  auto ret_addr =
      llvm::Intrinsic::getDeclaration(&module, llvm::Intrinsic::returnaddress);
  llvm::Value *args[] = {llvm::ConstantInt::get(i32_ty, 0)};

  for (const auto &[func, uses] : uses_by_func) {
    if (func->empty()) {
      continue;
    }

    auto &entry_block = func->getEntryBlock();
    if (entry_block.empty()) {
      continue;
    }

    auto new_ra = llvm::CallInst::Create(ret_addr, args, llvm::None,
                                         llvm::Twine::createNull(),
                                         &(entry_block.front()));

    for (auto use : uses) {
      use->set(new_ra);
    }
  }
}

}  // namespace

// Try to get an Value representing the address of `ea` as an entity, or return
// `nullptr`.
llvm::Constant *GetAddress(const Program &program, llvm::Module &module,
                           uint64_t ea, llvm::IRBuilder<> &builder,
                           llvm::PointerType *var_ptr_ty) {

  llvm::Constant *ret = nullptr;

  // Can we find a function at `ea`?
  if (auto func_decl = program.FindFunction(ea); func_decl) {
    ret = func_decl->DeclareInModule(CreateFunctionName(ea), module, true);

  // Can we find a variable at `ea`, or one that contains `ea`?
  } else if (auto var_decl = program.FindInVariable(ea, module.getDataLayout());
             var_decl) {
    DLOG(INFO) << "Found variable at: " << std::hex << ea << std::dec;

    if (var_decl->address == ea) {

      // This variable starts at exactly the bounds of a known variable
      ret = var_decl->DeclareInModule(CreateVariableName(ea), module, true);
    } else {

      // This variable is inside a known variable.
      // First, get a reference to it's enclosing variable
      auto enclosing_var = var_decl->DeclareInModule(
          CreateVariableName(var_decl->address), module, true);

      DLOG(INFO) << "... and its inside an allocated type: [" << std::hex
                 << var_decl->address << ", size:  " << std::hex
                 << module.getDataLayout().getTypeAllocSize(var_decl->type)
                 << "]" << std::dec;

      // second, build an expression to reference this variable in term of
      // its enclosing variable
      ret = llvm::dyn_cast<llvm::Constant>(remill::BuildPointerToOffset(
          builder, enclosing_var, ea - var_decl->address, var_ptr_ty));
    }

  // Can we find a byte (included anywhere in the Anvill Spec) that belongs to this program?
  } else if (auto bytes = program.FindBytesContaining(ea); bytes) {
    DLOG(INFO) << "Found a byte inside a memory area at: " << std::hex << ea
               << std::dec;
    auto start_address = bytes.Address();
    auto var_name = CreateVariableName(start_address);
    auto data = bytes.ToString();
    auto init_data = llvm::ConstantDataArray::get(
        module.getContext(), llvm::makeArrayRef(data.data(), data.size()));
    auto var_type = init_data->getType();

    auto new_gv = module.getOrInsertGlobal(var_name, var_type);
    if (auto gv = llvm::dyn_cast<llvm::GlobalVariable>(new_gv);
        gv && !gv->hasInitializer()) {
      gv->setInitializer(init_data);
    }
    if (start_address != ea) {

      // the address is inside an allocated type
      ret = llvm::dyn_cast<llvm::Constant>(remill::BuildPointerToOffset(
          builder, new_gv, ea - start_address, var_ptr_ty));

      DLOG(INFO) << "Built an offset to: " << std::hex << ea << " from: " << start_address
                << std::dec;
    }

  // In C a pointer can be one element beyond an array end.
  // This sometimes results in references to one byte beyond an array end
  // Handle this case, assuming the byte before `ea` exists
  } else if (auto prev_byte = program.FindByte(ea - 1u); ea && prev_byte) {
    LOG(ERROR) << "TODO: Handle case of one past a variable reference";
  } else {
    return nullptr;
  }

  if (ret) {
    const auto &dl = module.getDataLayout();
    auto &context = module.getContext();
    const auto intptr_ty =
        llvm::Type::getIntNTy(context, dl.getPointerSizeInBits(0));
    auto ptr_ret_val = llvm::ConstantExpr::getPtrToInt(ret, intptr_ty);
    CHECK(ptr_ret_val);
    return ptr_ret_val;
  }

  return nullptr;
}

// Recover higher-level memory accesses in the lifted functions declared
// in `program` and defined in `module`.
void RecoverMemoryAccesses(const Program &program, llvm::Module &module) {

  std::vector<std::tuple<llvm::Use *, Byte, llvm::Type *>> fixups;
  std::vector<std::tuple<llvm::Use *, Byte, llvm::Type *>> maybe_fixups;
  std::vector<std::tuple<llvm::Use *, uint64_t, llvm::Type *>> sp_fixups;
  std::vector<std::tuple<llvm::Use *, uint64_t, llvm::Type *>> ci_fixups;

  FindPossibleCrossReferences(program, module, "__anvill_sp", fixups,
                              maybe_fixups, sp_fixups);

  RecoverStackMemoryAccesses(sp_fixups, module);

  fixups.clear();
  maybe_fixups.clear();
  sp_fixups.clear();

  FindPossibleCrossReferences(program, module, "__anvill_pc", fixups,
                              maybe_fixups, ci_fixups);

  for (auto &var : module.globals()) {
    if (var.getName().startswith("__anvill_type")) {

      FindPossibleCrossReferences(program, module, var.getName(), fixups,
                                  maybe_fixups, ci_fixups);
    }
  }

  RecoverMemoryAccesses(program, module, fixups);
  RecoverMemoryAccesses(program, module, maybe_fixups);
  ReplaceImmediateIntegers(program, ci_fixups);


  fixups.clear();
  ci_fixups.clear();
  FindPossibleCrossReferences(program, module, "__anvill_ra", fixups, fixups,
                              ci_fixups);
  for (auto [use, byte, type] : fixups) {
    ci_fixups.emplace_back(use, byte.Address(), type);
  }

  RecoverReturnAddressUses(module, ci_fixups);
}

}  // namespace anvill
