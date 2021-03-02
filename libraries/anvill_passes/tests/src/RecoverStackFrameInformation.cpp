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

#include "RecoverStackFrameInformation.h"

#include <anvill/ABI.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

TEST_SUITE("RecoverStackFrameInformation") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    llvm::LLVMContext llvm_context;

    auto module =
        RunFunctionPass(llvm_context, "RecoverStackFrameInformation.ll",
                        CreateRecoverStackFrameInformation());

    // Verify the module
    std::string error_buffer;
    llvm::raw_string_ostream error_stream(error_buffer);

    auto succeeded = llvm::verifyModule(*module.get(), &error_stream) == 0;
    error_stream.flush();

    CHECK(succeeded);
    if (!succeeded) {
      std::string error_message = "Module verification failed";
      if (!error_buffer.empty()) {
        error_message += ": " + error_buffer;
      }

      std::cerr << error_message << std::endl;
    }
  }

  SCENARIO("Function analysis can recreate a simple, byte-array frame type") {
    GIVEN("a lifted function without stack information") {
      llvm::LLVMContext context;
      auto module = LoadTestData(context, "RecoverStackFrameInformation.ll");
      REQUIRE(module != nullptr);

      auto &function_list = module->getFunctionList();
      auto function_it =
          std::find_if(function_list.begin(), function_list.end(),

                       [](const llvm::Function &function) -> bool {
                         return !function.empty();
                       });

      REQUIRE(function_it != function_list.end());
      auto &function = *function_it;

      WHEN("enumerating instructions accessing the stack") {
        auto stack_ptr_usages_res =
            RecoverStackFrameInformation::EnumerateStackPointerUsages(function);

        REQUIRE(stack_ptr_usages_res.Succeeded());

        THEN(
            "all the store/load instructions using the stack pointer are returned") {
          auto stack_ptr_usages = stack_ptr_usages_res.TakeValue();
          CHECK(stack_ptr_usages.size() == 12U);
        }
      }

      WHEN("analyzing the stack frame") {
        auto stack_frame_analysis_res =
            RecoverStackFrameInformation::AnalyzeStackFrame(function);

        REQUIRE(stack_frame_analysis_res.Succeeded());

        THEN("lowest and highest relative offsets are returned") {
          // From the test data:
          //
          // clang-format off
          // store i32 %6, i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 12) to i32*), align 4
          // store i32 %5, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 12) to i32*), align 4
          // clanf-format on
          //
          // __anvill_sp - 16 - 12 = -28
          // __anvill_sp + 12 = 12
          //
          // The high boundary however is not 12, because we are writing a 32-bit
          // integers; we have to add sizeof(i32) to it, so it becomes 16
          //
          // low = -28
          // high = 16
          // size = 44

          auto stack_frame_analysis = stack_frame_analysis_res.TakeValue();
          CHECK(stack_frame_analysis.lowest_offset == -28);
          CHECK(stack_frame_analysis.highest_offset == 16);
          CHECK(stack_frame_analysis.size == 44U);

          for (auto &p : stack_frame_analysis.instruction_map) {
            auto &memory_info = p.second;
            CHECK(memory_info.type == llvm::Type::getInt32Ty(context));
          }
        }
      }

      WHEN("creating a new stack frame") {
        auto stack_frame_analysis_res =
            RecoverStackFrameInformation::AnalyzeStackFrame(function);

        REQUIRE(stack_frame_analysis_res.Succeeded());

        auto stack_frame_analysis = stack_frame_analysis_res.TakeValue();
        auto stack_frame_type_res = RecoverStackFrameInformation::GenerateStackFrameType(function, stack_frame_analysis);
        REQUIRE(stack_frame_type_res.Succeeded());

        THEN("a StructType containing a byte array is returned") {
          auto stack_frame_type = stack_frame_type_res.TakeValue();
          REQUIRE(stack_frame_type->getNumElements() == 1U);

          auto function_name = function.getName().str();
          auto expected_frame_type_name = function_name + kStackFrameTypeNameSuffix;
          REQUIRE(stack_frame_type->getName().str() == expected_frame_type_name);
          
          auto first_elem_type = stack_frame_type->getElementType(0U);
          REQUIRE(first_elem_type->isArrayTy());

          auto byte_array_type = llvm::dyn_cast<llvm::ArrayType>(first_elem_type);
          REQUIRE(byte_array_type != nullptr);

          auto byte_array_size = byte_array_type->getNumElements();
          CHECK(byte_array_size == 44U);

          auto module = function.getParent();
          auto data_layout = module->getDataLayout();
          auto frame_type_size = data_layout.getTypeAllocSize(stack_frame_type);
          CHECK(frame_type_size == 44U);
        }
      }
    }
  }
}

}  // namespace anvill
