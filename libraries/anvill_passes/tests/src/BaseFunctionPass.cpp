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

#include "BaseFunctionPass.h"

#include <doctest.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>

#include "RecoverStackFrameInformation.h"

namespace anvill {

TEST_SUITE("BaseFunctionPass") {
  TEST_CASE("BaseFunctionPass::InstructionReferencesStackPointer") {

    // Create a simple phi example
    llvm::LLVMContext context;
    auto module =
        std::make_unique<llvm::Module>("BaseFunctionPassTest", context);

    REQUIRE(module != nullptr);

    auto function_type =
        llvm::FunctionType::get(llvm::Type::getInt32Ty(context), {}, false);
    REQUIRE(function_type != nullptr);

    auto function =
        llvm::Function::Create(function_type, llvm::Function::ExternalLinkage,
                               "TestFunction", *module.get());
    REQUIRE(function != nullptr);

    llvm::IRBuilder<> builder(context);

    auto entry_bb = llvm::BasicBlock::Create(context, "entry", function);
    builder.SetInsertPoint(entry_bb);

    auto value_ptr = builder.CreateAlloca(builder.getInt32Ty());
    builder.CreateStore(llvm::Constant::getNullValue(builder.getInt32Ty()),
                        value_ptr);

    auto value = builder.CreateLoad(value_ptr);
    auto cond = builder.CreateICmpEQ(value, builder.getInt32(0));

    auto first_bb = llvm::BasicBlock::Create(context, "first", function);
    auto second_bb = llvm::BasicBlock::Create(context, "second", function);
    builder.CreateCondBr(cond, first_bb, second_bb);

    auto exit_bb = llvm::BasicBlock::Create(context, "exit", function);

    builder.SetInsertPoint(first_bb);
    auto first_bb_value =
        builder.CreateBinOp(llvm::Instruction::Add, value, builder.getInt32(1));

    builder.CreateBr(exit_bb);

    builder.SetInsertPoint(second_bb);
    auto second_bb_value =
        builder.CreateBinOp(llvm::Instruction::Add, value, builder.getInt32(2));

    builder.CreateBr(exit_bb);
    builder.SetInsertPoint(exit_bb);

    auto return_value = builder.CreatePHI(builder.getInt32Ty(), 2);
    return_value->addIncoming(first_bb_value, first_bb);
    return_value->addIncoming(second_bb_value, second_bb);

    builder.CreateRet(return_value);

    REQUIRE(llvm::verifyModule(*module.get()) == 0);

    // Attempt to run the InstructionReferencesStackPointer method on every
    // instruction
    auto data_layout = module->getDataLayout();

    for (auto &basic_block : *function) {
      for (auto &instruction : basic_block) {
        auto expected_false =
            BaseFunctionPass<std::monostate>::InstructionReferencesStackPointer(
                data_layout, instruction);

        CHECK(expected_false == false);
      }
    }
  }
}

}  // namespace anvill
