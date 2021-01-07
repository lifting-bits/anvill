/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#include "anvill/RecoverMemRefs.h"

#include <glog/logging.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstVisitor.h>
#include <remill/BC/Util.h>

#include "anvill/Decl.h"
#include "anvill/Program.h"
#include "anvill/Util.h"

namespace anvill {

namespace {

class MemRefVisitor : public llvm::InstVisitor<MemRefVisitor> {
 private:
  const Program &program;

 public:
  MemRefVisitor(const Program &program);
  void visitInstruction(llvm::Instruction &inst);
  void visitIntToPtr(llvm::IntToPtrInst &inst);
};

MemRefVisitor::MemRefVisitor(const Program &p) : program(p) {}

void MemRefVisitor::visitInstruction(llvm::Instruction &inst) {
  for (auto op : inst.operand_values()) {
    if (auto ce = llvm::dyn_cast<llvm::ConstantExpr>(op)) {
      auto ce_inst{ce->getAsInstruction()};
      ce_inst->insertBefore(&inst);
      ce->replaceAllUsesWith(ce_inst);
      visit(ce_inst);
    }
  }
}

void MemRefVisitor::visitIntToPtr(llvm::IntToPtrInst &inst) {
  const auto op{llvm::cast<llvm::ConstantInt>(inst.getOperand(0))};
  const auto addr{op->getLimitedValue()};
  auto module{inst.getModule()};
  llvm::IRBuilder<> ir(&inst);
  llvm::Value *val{nullptr};
  if (const auto vdecl = program.FindVariable(addr)) {
    const auto name{CreateVariableName(addr)};
    const auto gvar{vdecl->DeclareInModule(name, *module)};
    const auto type{gvar->getValueType()};
    if (type->isArrayTy() && type->getArrayElementType() ==
                                 inst.getType()->getPointerElementType()) {
      val = ir.CreateConstGEP2_64(gvar, 0U, 0U);
    } else {
      val = gvar;
    }
  } else if (auto fdecl = program.FindFunction(addr)) {
    val = fdecl->DeclareInModule(CreateFunctionName(addr), *module);
  }

  if (val) {
    inst.replaceAllUsesWith(val);
  }
}

}  // namespace

void RecoverMemoryReferences(const Program &program, llvm::Module &module) {
  MemRefVisitor mrv(program);
  mrv.visit(module);
}

}  // namespace anvill
