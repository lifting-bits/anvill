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

#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>

#include <iostream>

#include "BaseScenario.h"
#include "Utils.h"

namespace anvill {

TEST_SUITE("SplitStackFrameAtReturnAddress") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    llvm::LLVMContext llvm_context;
    auto module =
        LoadTestData(llvm_context, "SplitStackFrameAtReturnAddress.ll");

    REQUIRE(module != nullptr);

    auto error_manager = ITransformationErrorManager::Create();
    CHECK(RunFunctionPass(module.get(), CreateSplitStackFrameAtReturnAddress(
                                            *error_manager.get())));

    for (const auto &error : error_manager->ErrorList()) {
      CHECK_MESSAGE(false, error.description);
    }

    REQUIRE(error_manager->ErrorList().empty());
  }

  SCENARIO("Offsets can be converted to StructType element indexes") {
    GIVEN("a struct definition with 10 64-bit integers") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      // We can reuse the stack frame StructType for this
      auto frame_type = base->GenerateStackFrameType();

      WHEN("querying for offset 0") {
        auto module = base->Function()->getParent();

        auto elem_index_res =
            SplitStackFrameAtReturnAddress::StructOffsetToElementIndex(
                module, frame_type, 0);

        THEN("success is returned with a 0 element index") {
          REQUIRE(elem_index_res.Succeeded());
          CHECK(elem_index_res.Value() == 0UL);
        }
      }

      WHEN("querying for an invalid offset") {
        auto module = base->Function()->getParent();

        auto elem_index_res =
            SplitStackFrameAtReturnAddress::StructOffsetToElementIndex(
                module, frame_type, 1000);

        THEN("failure is returned") {
          CHECK(!elem_index_res.Succeeded());
        }
      }
    }
  }

  SCENARIO("Stack frame types can be deduced from function names") {
    GIVEN("a function without a matching StructType frame type") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      WHEN("querying for the frame type") {
        auto frame_type_res =
            SplitStackFrameAtReturnAddress::GetFunctionStackFrameType(
                *base->Function());

        THEN("an error is returned and the returned frame type is a nullptr") {
          CHECK(!frame_type_res.Succeeded());
        }
      }
    }

    GIVEN("a function with a matching StructType frame type") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      auto expected_frame_type = base->GenerateStackFrameType();

      WHEN("querying for the frame type") {
        auto frame_type_res =
            SplitStackFrameAtReturnAddress::GetFunctionStackFrameType(
                *base->Function());

        THEN("success is returned and frame_type is set to a valid pointer") {
          REQUIRE(frame_type_res.Succeeded());
          CHECK(frame_type_res.Value() == expected_frame_type);
        }
      }
    }
  }

  SCENARIO("Detecting stack frame allocation in a function") {
    GIVEN("a function without stack frame allocation") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      base->GenerateEmptyEntryBlock();

      WHEN("querying for the `alloca` instruction") {
        auto alloca_inst_res =
            SplitStackFrameAtReturnAddress::GetStackFrameAllocaInst(
                *base->Function());

        THEN("an error is returned") {
          REQUIRE(!alloca_inst_res.Succeeded());

          auto error = alloca_inst_res.TakeError();
          CHECK(error ==
                StackFrameSplitErrorCode::StackFrameAllocationNotFound);
        }
      }
    }

    GIVEN("a function with stack frame allocation") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      auto expected_alloca_inst =
          base->GenerateStackFrameAllocationEntryBlock();

      WHEN("querying for the `alloca` instruction") {
        auto alloca_inst_res =
            SplitStackFrameAtReturnAddress::GetStackFrameAllocaInst(
                *base->Function());

        THEN("the correct alloc instruction is returned") {
          REQUIRE(alloca_inst_res.Succeeded());

          auto alloca_inst = alloca_inst_res.TakeValue();
          CHECK(alloca_inst == expected_alloca_inst);
        }
      }
    }
  }

  SCENARIO("Detecting calls to the llvm.returnaddress intrinsic") {
    GIVEN("an empty function") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      base->GenerateEmptyEntryBlock();

      WHEN("querying for the `call` instruction to the intrinsic") {
        auto call_inst =
            SplitStackFrameAtReturnAddress::GetReturnAddressInstrinsicCall(
                *base->Function());

        THEN("a nullptr is returned") {
          CHECK(call_inst == nullptr);
        }
      }

      WHEN("querying for the retn addr store instr into the stack frame") {
        auto retn_addr_store_instr_res =
            SplitStackFrameAtReturnAddress::GetRetnAddressStoreInstructions(
                *base->Function());

        THEN("an error is returned") {
          REQUIRE(!retn_addr_store_instr_res.Succeeded());

          auto error = retn_addr_store_instr_res.TakeError();
          CHECK(error ==
                StackFrameSplitErrorCode::StackFrameAllocationNotFound);
        }
      }
    }

    GIVEN("a function with a call to the llvm.returnaddress intrinsic") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      base->GenerateStackFrameWithRetnIntrinsicEntryBlock();

      WHEN("querying for the `call` instruction to the intrinsic") {
        auto call_inst =
            SplitStackFrameAtReturnAddress::GetReturnAddressInstrinsicCall(
                *base->Function());

        THEN("a valid call instruction is returned") {
          CHECK(call_inst != nullptr);
        }
      }

      WHEN("querying for the retn addr store instr into the stack frame") {
        auto retn_addr_store_instr_res =
            SplitStackFrameAtReturnAddress::GetRetnAddressStoreInstructions(
                *base->Function());

        THEN("a valid store+off pair and alloc instruction are returned") {
          REQUIRE(retn_addr_store_instr_res.Succeeded());

          auto retn_addr_store_instr = retn_addr_store_instr_res.TakeValue();

          CHECK(retn_addr_store_instr.alloca_inst != nullptr);

          REQUIRE(retn_addr_store_instr.store_off_pairs.size() == 1U);
          const auto &store_and_offset =
              retn_addr_store_instr.store_off_pairs.front();

          auto store_instruction = std::get<0>(store_and_offset);
          auto store_offset = std::get<1>(store_and_offset);

          CHECK(store_instruction != nullptr);
          CHECK(store_offset == 16LL);
        }
      }
    }
  }

  SCENARIO("Stack frames can be split") {
    GIVEN("a function and a stack frame type with 10 64-bit ints") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      auto frame_type = base->GenerateStackFrameType();
      auto base_type_name = frame_type->getName().str();

      WHEN("splitting the stack frame in the center") {
        auto stack_frame_parts_res =
            SplitStackFrameAtReturnAddress::SplitStackFrameTypeAtOffset(
                *base->Function(), 40LL, frame_type);

        THEN("success is returned, with three new valid frame types") {
          REQUIRE(stack_frame_parts_res.Succeeded());

          auto stack_frame_parts = stack_frame_parts_res.TakeValue();
          REQUIRE(stack_frame_parts.size() == 3U);

          auto stack_frame_part0 = stack_frame_parts[0];
          CHECK(stack_frame_part0->getNumElements() == 5U);

          auto stack_frame_part0_name = stack_frame_part0->getName().str();
          CHECK(stack_frame_part0_name == base_type_name + "_part0");

          auto stack_frame_part1 = stack_frame_parts[1];
          CHECK(stack_frame_part1->getNumElements() == 1U);

          auto stack_frame_part1_name = stack_frame_part1->getName().str();
          CHECK(stack_frame_part1_name == base_type_name + "_part1");

          auto stack_frame_part2 = stack_frame_parts[2];
          CHECK(stack_frame_part2->getNumElements() == 4U);

          auto stack_frame_part2_name = stack_frame_part2->getName().str();
          CHECK(stack_frame_part2_name == base_type_name + "_part2");
        }
      }

      WHEN("splitting the stack frame at the first element") {
        auto stack_frame_parts_res =
            SplitStackFrameAtReturnAddress::SplitStackFrameTypeAtOffset(
                *base->Function(), 0LL, frame_type);

        THEN("success is returned, with two new valid frame types") {
          REQUIRE(stack_frame_parts_res.Succeeded());

          auto stack_frame_parts = stack_frame_parts_res.TakeValue();
          REQUIRE(stack_frame_parts.size() == 2U);

          auto stack_frame_part0 = stack_frame_parts[0];
          CHECK(stack_frame_part0->getNumElements() == 1U);

          auto stack_frame_part0_name = stack_frame_part0->getName().str();
          CHECK(stack_frame_part0_name == base_type_name + "_part0");

          auto stack_frame_part1 = stack_frame_parts[1];
          CHECK(stack_frame_part1->getNumElements() == 9U);

          auto stack_frame_part1_name = stack_frame_part1->getName().str();
          CHECK(stack_frame_part1_name == base_type_name + "_part1");
        }
      }

      WHEN("splitting the stack frame at the last element") {
        auto stack_frame_parts_res =
            SplitStackFrameAtReturnAddress::SplitStackFrameTypeAtOffset(
                *base->Function(), 72LL, frame_type);

        THEN("success is returned, with two new valid frame types") {
          REQUIRE(stack_frame_parts_res.Succeeded());

          auto stack_frame_parts = stack_frame_parts_res.TakeValue();
          REQUIRE(stack_frame_parts.size() == 2U);

          auto stack_frame_part0 = stack_frame_parts[0];
          CHECK(stack_frame_part0->getNumElements() == 9U);

          auto stack_frame_part0_name = stack_frame_part0->getName().str();
          CHECK(stack_frame_part0_name == base_type_name + "_part0");

          auto stack_frame_part1 = stack_frame_parts[1];
          CHECK(stack_frame_part1->getNumElements() == 1U);

          auto stack_frame_part1_name = stack_frame_part1->getName().str();
          CHECK(stack_frame_part1_name == base_type_name + "_part1");
        }
      }
    }
  }
}

}  // namespace anvill
