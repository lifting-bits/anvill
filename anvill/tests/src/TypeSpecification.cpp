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

#include "TypeSpecification.h"

#include <doctest.h>
#include <llvm/IR/Module.h>

#include <vector>

namespace anvill {

TEST_SUITE("TypeSpecification") {
  TEST_CASE("Basic string to type conversions") {
    struct TestEntry final {
      std::string spec;
      std::string expected_description;
      bool expected_outcome{false};
      bool expected_sized_attribute{false};
    };

    // clang-format off
    const std::vector<TestEntry> kTestEntryList = {
      { "broken specification!", "", false, false },
      { "l", "i64", true, true },
      { "L", "i64", true, true },
      { "i", "i32", true, true },
      { "**b", "i8**", true, true },

      // __libc_start_main
      { "(*(i**b**bi)i**b*(i**b**bi)*(vi)*(vi)*vi)", "i32 (i32 (i32, i8**, i8**)*, i32, i8**, i32 (i32, i8**, i8**)*, i32 ()*, i32 ()*, i8*)", true, false },
    };

    // clang-format on

    for (const auto &test_entry : kTestEntryList) {
      llvm::LLVMContext llvm_context;

      auto context_res =
          TypeSpecification::ParseSpec(llvm_context, test_entry.spec);

      CHECK(context_res.Succeeded() == test_entry.expected_outcome);
      if (!context_res.Succeeded()) {
        continue;
      }

      auto context = context_res.TakeValue();
      CHECK(context.type != nullptr);
      CHECK(context.sized == test_entry.expected_sized_attribute);
      CHECK(context.spec == test_entry.spec);
      CHECK(context.description == test_entry.expected_description);
    }
  }

  TEST_CASE("Basic type to string conversions") {
    struct TestEntry final {
      llvm::Type *type{nullptr};
      std::string expected_non_alphanum_output;
      std::string expected_alphanum_output;
    };

    llvm::LLVMContext llvm_context;
    llvm::Module module("ITypeSpecificationTests", llvm_context);

    const auto &data_layout = module.getDataLayout();

    // clang-format off
    std::vector<TestEntry> kTestEntryList = {
      { llvm::Type::getInt8Ty(llvm_context), "b", "b" },
      { llvm::Type::getInt16Ty(llvm_context), "h", "h" },
      { llvm::Type::getInt32Ty(llvm_context), "i", "i" },
      { llvm::Type::getInt64Ty(llvm_context), "l", "l" },
      { llvm::Type::getFloatTy(llvm_context), "f", "f"},

      { llvm::Type::getInt8PtrTy(llvm_context), "*b", "_Sb" },
      { llvm::Type::getInt16PtrTy(llvm_context), "*h", "_Sh" },
      { llvm::Type::getInt32PtrTy(llvm_context), "*i", "_Si" },
      { llvm::Type::getInt64PtrTy(llvm_context), "*l", "_Sl" },
      { llvm::Type::getFloatPtrTy(llvm_context), "*f", "_Sf"},
    };

    // clang-format on

    std::vector<llvm::Type *> struct_part_list(
        10, llvm::Type::getInt16Ty(llvm_context));

    auto struct_type = llvm::StructType::create(struct_part_list, "", false);

    kTestEntryList.push_back(
        {struct_type, "=0{hhhhhhhhhh}", "=0_Ehhhhhhhhhh_F"});

    auto array_type = llvm::ArrayType::get(struct_type, 100);

    kTestEntryList.push_back(
        {array_type, "[=0{hhhhhhhhhh}x100]", "_C=0_Ehhhhhhhhhh_Fx100_D"});

    std::vector<llvm::Type *> struct_part_list2 = {array_type, struct_type};
    auto struct_type2 = llvm::StructType::create(struct_part_list2, "", false);

    kTestEntryList.push_back({struct_type2, "=0{[=1{hhhhhhhhhh}x100]%1}",
                              "=0_E_C=1_Ehhhhhhhhhh_Fx100_D_M1_F"});

    auto function_type =
        llvm::FunctionType::get(array_type, {struct_type2}, false);

    kTestEntryList.push_back(
        {function_type, "(=0{[=1{hhhhhhhhhh}x100]%1}[%1x100])",
         "_A=0_E_C=1_Ehhhhhhhhhh_Fx100_D_M1_F_C_M1x100_D_B"});

    auto variadic_function_type =
        llvm::FunctionType::get(array_type, {struct_type2}, false);

    kTestEntryList.push_back(
        {variadic_function_type, "(=0{[=1{hhhhhhhhhh}x100]%1}[%1x100])",
         "_A=0_E_C=1_Ehhhhhhhhhh_Fx100_D_M1_F_C_M1x100_D_B"});

    for (const auto &test_entry : kTestEntryList) {
      auto without_alphanum = ITypeSpecification::TypeToString(
          *test_entry.type, data_layout, false);

      auto with_alphanum =
          ITypeSpecification::TypeToString(*test_entry.type, data_layout, true);

      CHECK(without_alphanum == test_entry.expected_non_alphanum_output);
      CHECK(with_alphanum == test_entry.expected_alphanum_output);
    }

    //
    // These types should differ, just issue a warning for now
    //

    // variadic function vs non-variadic
    auto variadic_func_description = ITypeSpecification::TypeToString(
        *variadic_function_type, data_layout, false);

    auto non_variadic_func_description =
        ITypeSpecification::TypeToString(*function_type, data_layout, false);

    WARN(variadic_func_description != non_variadic_func_description);

    auto variadic_alphanum_func_description = ITypeSpecification::TypeToString(
        *variadic_function_type, data_layout, true);

    auto non_variadic_alphanum_func_description =
        ITypeSpecification::TypeToString(*function_type, data_layout, true);

    WARN(variadic_alphanum_func_description !=
         non_variadic_alphanum_func_description);

    // packed struct vs non-packed
    std::vector<llvm::Type *> struct_part_list3 = {array_type, struct_type,
                                                   array_type, struct_type};

    auto non_packed_struct_type =
        llvm::StructType::create(struct_part_list3, "", false);

    auto packed_struct_type =
        llvm::StructType::create(struct_part_list3, "", true);

    auto non_packed_struct = ITypeSpecification::TypeToString(
        *non_packed_struct_type, data_layout, false);

    auto packed_struct = ITypeSpecification::TypeToString(*packed_struct_type,
                                                          data_layout, false);

    WARN(non_packed_struct != packed_struct);

    auto alphanum_non_packed_struct = ITypeSpecification::TypeToString(
        *non_packed_struct_type, data_layout, true);

    auto alphanum_packed_struct = ITypeSpecification::TypeToString(
        *packed_struct_type, data_layout, true);

    WARN(alphanum_non_packed_struct != alphanum_packed_struct);
  }

  TEST_CASE("Simple spec -> type -> spec roundtrip") {

    // Do not mark these as errors yet, as some of these tests
    // are not working

    // clang-format off
    const std::vector<std::string> kTestSpecList = {
      "(*(i**b**bi)i**b*(i**b**bi)*(vi)*(vi)*vi)",
      "b",
      "h",
      "i",
      "l",
      "f",
      "*b",
      "*h",
      "*i",
      "*l",
      "*f",
      "=0{[=1{hhhhhhhhhh}x100]%1}",
      "(=0{[=1{hhhhhhhhhh}x100]%1}[%1x100])",
    };

    // clang-format on

    llvm::LLVMContext llvm_context;
    llvm::Module module("ITypeSpecificationTests", llvm_context);

    const auto &data_layout = module.getDataLayout();

    for (const auto &test_spec : kTestSpecList) {
      auto context_res = TypeSpecification::ParseSpec(llvm_context, test_spec);
      REQUIRE(context_res.Succeeded());

      auto context = context_res.TakeValue();

      REQUIRE(context.type != nullptr);
      REQUIRE(context.spec == test_spec);

      auto generated_spec =
          ITypeSpecification::TypeToString(*context.type, data_layout, false);
      WARN(generated_spec == test_spec);
    }
  }
}

}  // namespace anvill
