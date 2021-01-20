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

#include <remill/BC/Compat/Error.h>

#include <cstdint>

namespace llvm {
class Constant;
class ConstantExpr;
class GlobalValue;
class Instruction;
class Module;
class Type;
class Value;
class CallInst;
}  // namespace llvm
namespace anvill {

class Program;

// Fold constant expressions into possible cross-references.
class XrefExprFolder {
 public:
  XrefExprFolder(const Program &program_, llvm::Module &module_);

  const Program &program;
  llvm::Module &module;

  // Is this relative to an immediate constant?
  bool is_ci_relative{false};

  // This this relative to the program counter or something that we could
  // consider to be program-counter relative?
  bool is_pc_relative{false};

  // Is this relative to the stack pointer?
  bool is_sp_relative{false};

  // Is this relative to the return address?
  bool is_ra_relative{false};

  // Is this relative to a global variable?
  bool is_gv_relative{false};

  // Do we think this is a pointer?
  bool is_pointer{false};

  // Type hinted by IDA or Binja
  llvm::Type *hinted_type{nullptr};

  // Might tell us if there are aspects of this xref that might disqualify
  // it as an actual xref.
  unsigned left_shift_amount{0};
  unsigned right_shift_amount{0};
  uint64_t bits_xor{0};
  uint64_t bits_and{0};

  // Was there an error?
  llvm::Error error;

  void Reset(void);
  uint64_t Visit(llvm::Value *v);
  uint64_t VisitInst(llvm::Instruction *ce);
  uint64_t VisitConst(llvm::Constant *c);

 private:
  uint64_t VisitGEP(llvm::Value *gep);
  uint64_t VisitAdd(llvm::Value *lhs, llvm::Value *rhs);
  uint64_t VisitSub(llvm::Value *lhs, llvm::Value *rhs);
  uint64_t VisitMul(llvm::Value *lhs, llvm::Value *rhs);
  uint64_t VisitAnd(llvm::Value *lhs, llvm::Value *rhs);
  uint64_t VisitOr(llvm::Value *lhs, llvm::Value *rhs);
  uint64_t VisitXor(llvm::Value *lhs, llvm::Value *rhs);
  uint64_t VisitShl(llvm::Value *lhs, llvm::Value *rhs);
  uint64_t VisitLShr(llvm::Value *lhs, llvm::Value *rhs);
  uint64_t VisitAShr(llvm::Value *lhs_op, llvm::Value *rhs_op);
  uint64_t VisitCall(llvm::CallInst *call);
  int64_t Signed(uint64_t val, llvm::Value *op);
  uint64_t VisitICmp(llvm::Instruction *inst);
  uint64_t VisitICmp(llvm::ConstantExpr *ce);
  uint64_t VisitICmp(unsigned pred, llvm::Value *lhs_op, llvm::Value *rhs_op);
  uint64_t VisitSelect(llvm::Value *cond, llvm::Value *if_true,
                       llvm::Value *if_false);
  uint64_t VisitZExt(llvm::Value *op, llvm::Type *type);
  uint64_t VisitSExt(llvm::Value *op, llvm::Type *type);
  uint64_t VisitTrunc(llvm::Value *op, llvm::Type *type);
  std::pair<bool, uint64_t> TryResolveGlobal(llvm::GlobalValue *gv);
};


// Recover higher-level memory accesses in the lifted functions declared
// in `program` and defined in `module`.
void RecoverMemoryAccesses(const Program &program, llvm::Module &module);

}  // namespace anvill
