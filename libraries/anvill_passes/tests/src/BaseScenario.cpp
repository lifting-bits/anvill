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

#include "BaseScenario.h"

#include <llvm/IR/IRBuilder.h>

namespace anvill {

namespace {

const std::string kTestModuleName{"TestModule"};
const std::string kTestFunctionName{"TestFunction"};
const std::string kTestFrameTypeName{"TestFunction.frame_type"};

}  // namespace

struct BaseScenario::PrivateData final {
  llvm::LLVMContext context;
  std::unique_ptr<llvm::Module> module;

  llvm::Function *function;

  bool entry_block_generated{false};
  bool frame_type_generated{false};
};

bool BaseScenario::Create(Ptr &obj) {
  obj.reset();

  try {
    obj.reset(new BaseScenario());
    return true;

  } catch (const std::bad_alloc &) {
    return false;
  }
}

BaseScenario::~BaseScenario() {}

void BaseScenario::GenerateEmptyEntryBlock() {
  if (d->entry_block_generated) {
    throw std::runtime_error("The entry block has been already generated");
  }

  auto entry_bb = llvm::BasicBlock::Create(d->context, "entry", d->function);

  llvm::IRBuilder<> builder(d->context);
  builder.SetInsertPoint(entry_bb);
  builder.CreateRetVoid();

  d->entry_block_generated = true;
}

llvm::AllocaInst *BaseScenario::GenerateStackFrameAllocationEntryBlock() {
  if (d->entry_block_generated) {
    throw std::runtime_error("The entry block has been already generated");
  }

  llvm::StructType *frame_type{nullptr};
  if (!d->frame_type_generated) {
    frame_type = GenerateStackFrameType();
  } else {
    frame_type = d->module->getTypeByName(kTestFrameTypeName);
  }

  if (frame_type == nullptr) {
    throw std::runtime_error("Failed to acquire the function frame type");
  }

  auto entry_bb = llvm::BasicBlock::Create(d->context, "entry", d->function);

  llvm::IRBuilder<> builder(d->context);
  builder.SetInsertPoint(entry_bb);

  auto alloca_inst = builder.CreateAlloca(frame_type);
  builder.CreateRetVoid();

  d->entry_block_generated = true;

  return alloca_inst;
}

SplitStackFrameAtReturnAddress::StoreInstAndOffsetPair
BaseScenario::GenerateStackFrameWithRetnIntrinsicEntryBlock() {

  if (d->entry_block_generated) {
    throw std::runtime_error("The entry block has been already generated");
  }

  llvm::StructType *frame_type{nullptr};
  if (!d->frame_type_generated) {
    frame_type = GenerateStackFrameType();
  } else {
    frame_type = d->module->getTypeByName(kTestFrameTypeName);
  }

  if (frame_type == nullptr) {
    throw std::runtime_error("Failed to acquire the function frame type");
  }

  auto entry_bb = llvm::BasicBlock::Create(d->context, "entry", d->function);

  llvm::IRBuilder<> builder(d->context);
  builder.SetInsertPoint(entry_bb);

  auto retn_address_intr_type =
      llvm::FunctionType::get(builder.getInt64Ty(), {}, false);

  auto retn_address_intr = llvm::Function::Create(
      retn_address_intr_type, llvm::GlobalValue::ExternalLinkage,
      "llvm.returnaddress", *d->module.get());

  auto retn_address = builder.CreateCall(retn_address_intr, {});
  auto stack_frame = builder.CreateAlloca(frame_type);

  auto retn_dest_index = 2;
  auto retn_addr_dest = builder.CreateGEP(
      stack_frame, {builder.getInt32(0), builder.getInt32(retn_dest_index)});

  auto store_inst = builder.CreateStore(retn_address, retn_addr_dest);

  builder.CreateRetVoid();

  d->entry_block_generated = true;
  return std::make_pair(store_inst, retn_dest_index * 8LL);
}

llvm::StructType *BaseScenario::GenerateStackFrameType() {
  if (d->frame_type_generated) {
    throw std::runtime_error("The frame type has already been generated");
  }

  std::vector<llvm::Type *> frame_type_list(10,
                                            llvm::Type::getInt64Ty(d->context));

  auto frame_type =
      llvm::StructType::create(frame_type_list, kTestFrameTypeName, false);

  d->frame_type_generated = true;
  return frame_type;
}

llvm::Function *BaseScenario::Function() const {
  return d->function;
}

llvm::LLVMContext &BaseScenario::Context() const {
  return d->context;
}

BaseScenario::BaseScenario() : d(new PrivateData) {
  d->module = std::make_unique<llvm::Module>(kTestModuleName, d->context);

  auto function_type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(d->context), {}, false);

  d->function =
      llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
                             kTestFunctionName, *d->module.get());
}


}  // namespace anvill
