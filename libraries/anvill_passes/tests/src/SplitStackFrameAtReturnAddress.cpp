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

    CHECK(
        RunFunctionPass(module.get(), CreateSplitStackFrameAtReturnAddress()));
  }

  SCENARIO("Offsets can be converted to StructType element indexes") {
    GIVEN("a struct definition with 10 64-bit integers") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      // We can reuse the stack frame StructType for this
      auto frame_type = base->GenerateStackFrameType();

      WHEN("querying for offset 0") {
        auto module = base->Function()->getParent();

        std::uint32_t elem_index{1};
        auto succeeded =
            SplitStackFrameAtReturnAddress::StructOffsetToElementIndex(
                elem_index, module, frame_type, 0);

        THEN("success is returned with a 0 element index") {
          CHECK(succeeded);
          CHECK(elem_index == 0UL);
        }
      }

      WHEN("querying for an invalid offset") {
        auto module = base->Function()->getParent();

        std::uint32_t elem_index{1};
        auto succeeded =
            SplitStackFrameAtReturnAddress::StructOffsetToElementIndex(
                elem_index, module, frame_type, 1000);

        THEN("failure is returned") {
          CHECK(succeeded == false);
          CHECK(elem_index == 0UL);
        }
      }
    }
  }

  SCENARIO("Stack frame types can be deduced from function names") {
    GIVEN("a function without a matching StructType frame type") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      WHEN("querying for the frame type") {
        auto frame_type = reinterpret_cast<const llvm::StructType *>(1);

        auto frame_type_found =
            SplitStackFrameAtReturnAddress::GetFunctionStackFrameType(
                frame_type, *base->Function());

        THEN("an error is returned and the returned frame type is a nullptr") {
          CHECK(frame_type == nullptr);
          CHECK(!frame_type_found);
        }
      }
    }

    GIVEN("a function with a matching StructType frame type") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      auto expected_frame_type = base->GenerateStackFrameType();

      WHEN("querying for the frame type") {
        const llvm::StructType *frame_type{nullptr};

        auto frame_type_found =
            SplitStackFrameAtReturnAddress::GetFunctionStackFrameType(
                frame_type, *base->Function());

        THEN("success is returned and frame_type is set to a valid pointer") {
          CHECK(frame_type == expected_frame_type);
          CHECK(frame_type_found);
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
        auto alloca_inst =
            SplitStackFrameAtReturnAddress::GetStackFrameAllocaInst(
                *base->Function());

        THEN("a nullptr is returned") {
          CHECK(alloca_inst == nullptr);
        }
      }
    }

    GIVEN("a function with stack frame allocation") {
      BaseScenario::Ptr base;
      REQUIRE(BaseScenario::Create(base));

      auto expected_alloca_inst =
          base->GenerateStackFrameAllocationEntryBlock();

      WHEN("querying for the `alloca` instruction") {
        auto alloca_inst =
            SplitStackFrameAtReturnAddress::GetStackFrameAllocaInst(
                *base->Function());

        THEN("the correct alloc instruction is returned") {
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
        std::vector<SplitStackFrameAtReturnAddress::StoreInstAndOffsetPair>
            store_off_pairs = {std::make_pair(nullptr, 0),
                               std::make_pair(nullptr, 0)};

        auto alloca_inst = reinterpret_cast<llvm::AllocaInst *>(1);

        auto found =
            SplitStackFrameAtReturnAddress::GetRetnAddressStoreInstructions(
                store_off_pairs, alloca_inst, *base->Function());

        THEN("nothing is returned") {
          CHECK(found == false);
          CHECK(alloca_inst == nullptr);
          CHECK(store_off_pairs.empty());
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
        std::vector<SplitStackFrameAtReturnAddress::StoreInstAndOffsetPair>
            store_off_pairs = {std::make_pair(nullptr, 0),
                               std::make_pair(nullptr, 0)};

        llvm::AllocaInst *alloca_inst{nullptr};

        auto found =
            SplitStackFrameAtReturnAddress::GetRetnAddressStoreInstructions(
                store_off_pairs, alloca_inst, *base->Function());

        THEN("a valid store+off pair and alloc instruction are returned") {
          CHECK(found);

          CHECK(alloca_inst != nullptr);

          REQUIRE(store_off_pairs.size() == 1U);
          const auto &store_and_offset = store_off_pairs.front();

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
        std::vector<llvm::StructType *> stack_frame_parts;

        auto error =
            SplitStackFrameAtReturnAddress::SplitStackFrameTypeAtOffset(
                stack_frame_parts, *base->Function(), 40LL, frame_type);

        THEN("success is returned, with three new valid frame types") {
          CHECK(error == SplitStackFrameAtReturnAddress::Error::Success);
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
        std::vector<llvm::StructType *> stack_frame_parts;

        auto error =
            SplitStackFrameAtReturnAddress::SplitStackFrameTypeAtOffset(
                stack_frame_parts, *base->Function(), 0LL, frame_type);

        THEN("success is returned, with two new valid frame types") {
          CHECK(error == SplitStackFrameAtReturnAddress::Error::Success);
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
        std::vector<llvm::StructType *> stack_frame_parts;

        auto error =
            SplitStackFrameAtReturnAddress::SplitStackFrameTypeAtOffset(
                stack_frame_parts, *base->Function(), 72LL, frame_type);

        THEN("success is returned, with two new valid frame types") {
          CHECK(error == SplitStackFrameAtReturnAddress::Error::Success);
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
