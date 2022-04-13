/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/ABI.h>
#include <anvill/Arch.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include <anvill/Lifters.h>
#include <array>
#include <sstream>
#include <anvill/Providers.h>
#include <anvill/Passes/RecoverBasicStackFrame.h>
#include "RecoverBasicStackFrame.cpp"
#include "Utils.h"

namespace anvill {

TEST_SUITE("RecoverBasicStackFrame") {
  TEST_CASE("Run the whole pass on a well-formed function") {
    static const StackFrameStructureInitializationProcedure
        kInitStackSettings[] = {
            StackFrameStructureInitializationProcedure::kNone,
            StackFrameStructureInitializationProcedure::kZeroes,
            StackFrameStructureInitializationProcedure::kUndef,
            StackFrameStructureInitializationProcedure::kSymbolic};

    static const std::size_t kTestPaddingSettings[] = {0, 32, 64};

    for (const auto &platform : GetSupportedPlatforms()) {
      for (auto init_strategy : kInitStackSettings) {
        for (auto padding_bytes : kTestPaddingSettings) {
          llvm::LLVMContext context;
          auto module =
              LoadTestData(context, "RecoverStackFrameInformation.ll");

          REQUIRE(module != nullptr);

          auto arch = BuildArch(context, remill::GetArchName(platform.arch),
                                remill::GetOSName(platform.os));

          REQUIRE(arch != nullptr);

          auto ctrl_flow_provider =
              anvill::NullControlFlowProvider();

          TypeDictionary tyDict(context);

          NullTypeProvider ty_prov(tyDict);
          NullMemoryProvider mem_prov;
          anvill::LifterOptions lift_options(
              arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);
          
          lift_options.stack_frame_recovery_options.stack_frame_struct_init_procedure = init_strategy;
          lift_options.stack_frame_recovery_options.stack_frame_lower_padding =
              lift_options.stack_frame_recovery_options.stack_frame_higher_padding = padding_bytes / 2U;

          CHECK(RunFunctionPass(
              module.get(), RecoverBasicStackFrame(lift_options.stack_frame_recovery_options)));

        }
      }
    }
  }


  SCENARIO("Function analysis can recreate a simple, byte-array frame type") {

    GIVEN("a lifted function without stack information") {
      llvm::LLVMContext context;
      auto module = LoadTestData(context, "RecoverStackFrameInformation.ll");
      REQUIRE(module != nullptr);
      auto arch = BuildArch(context, remill::ArchName::kArchAMD64,
                            remill::OSName::kOSLinux);
      REQUIRE(arch != nullptr);

      auto ctrl_flow_provider =
          anvill::NullControlFlowProvider();

      TypeDictionary tyDict(context);

      NullTypeProvider ty_prov(tyDict);
      NullMemoryProvider mem_prov;
      anvill::LifterOptions lift_options(
          arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);


      auto &function_list = module->getFunctionList();
      auto function_it =
          std::find_if(function_list.begin(), function_list.end(),

                       [](const llvm::Function &function) -> bool {
                         return !function.empty();
                       });

      REQUIRE(function_it != function_list.end());
      auto &function = *function_it;
      WHEN("enumerating stack pointer usages") {
        auto stack_ptr_usages =
            EnumerateStackPointerUsages(function);

        THEN(
            "all the uses for the instruction operands referencing the __anvill_sp symbol are returned") {

          // From the test data, you can see we have 12 instructions referencing
          // the `__anvill_sp` symbol. Two of these, are `store` instructions
          // that have the symbol on both operands.
          CHECK(stack_ptr_usages.size() == 14U);
        }
      }

      WHEN("analyzing the stack frame") {
        auto stack_frame_analysis =
            AnalyzeStackFrame(function, lift_options.stack_frame_recovery_options);

        THEN("lowest and highest relative offsets are returned") {

          // From the test data, you can see we have 12 instructions referencing
          // the `__anvill_sp` symbol
          //
          // The boundaries we should find are:
          // __anvill_sp - 16 - 12 = -28
          // __anvill_sp + 12 = 12
          //
          // The high boundary however is not 12, because we are writing a 32-bit
          // integer; we have to add sizeof(i32) to it, so it becomes 16
          //
          // low = -28
          // high = 16
          // size = 44

          CHECK(stack_frame_analysis.lowest_offset == -28);
          CHECK(stack_frame_analysis.highest_offset == 16);
          CHECK(stack_frame_analysis.size == 44U);

          // Usages of the `__anvill_sp` symbol is 14, because two of the 12
          // instructions we have are referencing the stack from both
          // operands
          CHECK(stack_frame_analysis.instruction_uses.size() == 14U);
        }
      }

      WHEN("creating a new stack frame with no padding bytes") {
        auto stack_frame_analysis = AnalyzeStackFrame(
            function, lift_options.stack_frame_recovery_options);
        auto stack_frame_word_type = lift_options.arch->AddressType();
        auto stack_frame_type = GenerateStackFrameType(
                function, lift_options.stack_frame_recovery_options,
                stack_frame_analysis, 0, stack_frame_word_type);

        THEN("a StructType containing a word array is returned") {
          REQUIRE(stack_frame_type->getNumElements() == 1U);

          auto function_name = function.getName().str();
          auto expected_frame_type_name =
              function_name + kStackFrameTypeNameSuffix;
          REQUIRE(stack_frame_type->getName().str() ==
                  expected_frame_type_name);

          auto first_elem_type = stack_frame_type->getElementType(0U);
          REQUIRE(first_elem_type->isArrayTy());

          auto byte_array_type =
              llvm::dyn_cast<llvm::ArrayType>(first_elem_type);
          REQUIRE(byte_array_type != nullptr);

          CHECK(stack_frame_analysis.size == 44u);

          auto word_array_size = byte_array_type->getNumElements();
          std::cout << word_array_size << std::endl;
          // type is always address size
          CHECK(word_array_size == (48u / (lift_options.arch->address_size / 8)));

          auto module = function.getParent();
          auto data_layout = module->getDataLayout();
          auto frame_type_size = data_layout.getTypeAllocSize(stack_frame_type);
          CHECK(frame_type_size == 48U);
        }
      }

      WHEN("creating a new stack frame with additional padding bytes") {
        auto stack_frame_analysis = AnalyzeStackFrame(
            function, lift_options.stack_frame_recovery_options);
        auto stack_frame_word_type = lift_options.arch->AddressType();
        auto stack_frame_type = GenerateStackFrameType(
            function, lift_options.stack_frame_recovery_options,
            stack_frame_analysis, 128U, stack_frame_word_type);

        THEN(
            "a StructType containing a word array along with the padding is returned") {
          REQUIRE(stack_frame_type->getNumElements() == 1U);

          auto function_name = function.getName().str();
          auto expected_frame_type_name =
              function_name + kStackFrameTypeNameSuffix;
          REQUIRE(stack_frame_type->getName().str() ==
                  expected_frame_type_name);

          auto first_elem_type = stack_frame_type->getElementType(0U);
          REQUIRE(first_elem_type->isArrayTy());

          auto byte_array_type =
              llvm::dyn_cast<llvm::ArrayType>(first_elem_type);
          REQUIRE(byte_array_type != nullptr);

          CHECK(stack_frame_analysis.size == 44u);

          auto word_array_size = byte_array_type->getNumElements();
          CHECK(word_array_size == (176u / (lift_options.arch->address_size / 8)));

          auto module = function.getParent();
          auto data_layout = module->getDataLayout();
          auto frame_type_size = data_layout.getTypeAllocSize(stack_frame_type);
          CHECK(frame_type_size == 176U);
        }
      }
    }
  }

  SCENARIO("Applying stack frame recovery") {
    GIVEN("a well formed function") {
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
      auto arch = BuildArch(context, remill::ArchName::kArchAMD64,
                            remill::OSName::kOSLinux);
      REQUIRE(arch != nullptr);

      auto ctrl_flow_provider =
          anvill::NullControlFlowProvider();

      TypeDictionary tyDict(context);

      NullTypeProvider ty_prov(tyDict);
      NullMemoryProvider mem_prov;
      anvill::LifterOptions lift_options(
          arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

      WHEN("recovering the stack frame") {
        auto stack_frame_analysis = AnalyzeStackFrame(function, lift_options.stack_frame_recovery_options);
        auto arch = BuildArch(context, remill::ArchName::kArchAMD64,
                              remill::OSName::kOSLinux);

        lift_options.stack_frame_recovery_options.stack_frame_struct_init_procedure =
            StackFrameStructureInitializationProcedure::kZeroes;
        UpdateFunction(
            function, lift_options.stack_frame_recovery_options, stack_frame_analysis);

        THEN("the function is updated to use the new stack frame structure") {
          auto &entry_block = function.getEntryBlock();

          // Find the `alloca` instruction that should appear
          // as the first instruction in the entry block
          llvm::AllocaInst *alloca_inst{nullptr};

          {
            auto first_instr_it = entry_block.begin();
            REQUIRE(first_instr_it != entry_block.end());

            auto first_instr = &(*first_instr_it);

            alloca_inst = llvm::dyn_cast<llvm::AllocaInst>(first_instr);
          }

          CHECK(alloca_inst != nullptr);

          // We have 12 instructions referencing the `__anvill_sp` symbol; however, two
          // of those are `store` operations that have 2 references each.
          //
          // We should then have 14 GEP instructions
          std::size_t frame_gep_count{0U};
          for (const auto &instr : entry_block) {
            auto gep_instr = llvm::dyn_cast<llvm::GetElementPtrInst>(&instr);
            if (gep_instr == nullptr) {
              continue;
            }

            ++frame_gep_count;
          }

          CHECK(frame_gep_count == 14U);

          // If we run a second stack analysis, we should no longer find any
          // stack frame operation to recover
          stack_frame_analysis = AnalyzeStackFrame(function, lift_options.stack_frame_recovery_options);

          CHECK(stack_frame_analysis.instruction_uses.empty());
        }
      }
    }
  }
}

}  // namespace anvill
