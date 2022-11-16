/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Type.h>

#include <doctest/doctest.h>
#include <llvm/IR/Module.h>
#include <remill/BC/Version.h>

#include <vector>

namespace anvill {

TEST_SUITE("TypeSpecifier") {
  TEST_CASE("Basic string to type conversions") {
    struct TestEntry final {
      TypeSpec spec;
      std::string expected_description;
      bool expected_outcome{false};
    };

    const std::vector<TestEntry> kTestEntryList = {
        {BaseType::Int64, "i64", true},
        {BaseType::Int32, "i32", true},
        {std::make_shared<PointerType>(BaseType::Void, false), "ptr", true},
        {std::make_shared<FunctionType>(
             BaseType::Void,
             std::vector<TypeSpec>{
                 BaseType::Int32, BaseType::Int8,
                 std::make_shared<PointerType>(BaseType::Void, false),
                 BaseType::Int32},
             false),
         "void (i32, i8, ptr, i32)", true},
    };

    for (const auto &test_entry : kTestEntryList) {
      llvm::LLVMContext llvm_context;
#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
      llvm_context.enableOpaquePointers();
#endif
      llvm::DataLayout dl("e-m:e-i64:64-f80:128-n8:16:32:64-S128");

      anvill::TypeDictionary type_dict(llvm_context);
      anvill::TypeTranslator specifier(type_dict, dl);

      auto context_res = specifier.DecodeFromSpec(test_entry.spec);

      CHECK_EQ(context_res.Succeeded(), test_entry.expected_outcome);
      if (!context_res.Succeeded()) {
        continue;
      }

      llvm::Type *type = context_res.TakeValue();
      // CHECK_EQ(test_entry.spec, specifier.EncodeToString(type));

      std::string str;
      llvm::raw_string_ostream os(str);
      type->print(os);
      os.flush();
      CHECK_EQ(str, test_entry.expected_description);
    }
  }

  /*
  TEST_CASE("Basic type to string conversions") {
    struct TestEntry final {
      llvm::Type *type{nullptr};
      std::string expected_non_alphanum_output;
      std::string expected_alphanum_output;
    };

    llvm::LLVMContext llvm_context;
#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
    llvm_context.enableOpaquePointers();
#endif
    llvm::Module module("TypeSpecifierTests", llvm_context);

    const auto &data_layout = module.getDataLayout();

    // clang-format off
    std::vector<TestEntry> kTestEntryList = {
      { llvm::Type::getInt8Ty(llvm_context), "b", "b" },
      { llvm::Type::getInt16Ty(llvm_context), "h", "h" },
      { llvm::Type::getInt32Ty(llvm_context), "i", "i" },
      { llvm::Type::getInt64Ty(llvm_context), "l", "l" },
      { llvm::Type::getFloatTy(llvm_context), "f", "f"},

      { llvm::Type::getInt8PtrTy(llvm_context), "*", "_S" },
      { llvm::Type::getInt16PtrTy(llvm_context), "*", "_S" },
      { llvm::Type::getInt32PtrTy(llvm_context), "*", "_S" },
      { llvm::Type::getInt64PtrTy(llvm_context), "*", "_S" },
      { llvm::Type::getFloatPtrTy(llvm_context), "*", "_S"},
    };

    // clang-format on

    std::vector<llvm::Type *> struct_part_list(
        10, llvm::Type::getInt16Ty(llvm_context));

    auto struct_type = llvm::StructType::create(struct_part_list, "", false);

    kTestEntryList.push_back(
        {struct_type, "=0{hhhhhhhhhh}", "_X0_Ehhhhhhhhhh_F"});

    auto array_type = llvm::ArrayType::get(struct_type, 100);

    kTestEntryList.push_back(
        {array_type, "[=0{hhhhhhhhhh}x100]", "_C_X0_Ehhhhhhhhhh_Fx100_D"});

    std::vector<llvm::Type *> struct_part_list2 = {array_type, struct_type};
    auto struct_type2 = llvm::StructType::create(struct_part_list2, "", false);

    kTestEntryList.push_back({struct_type2, "=0{[=1{hhhhhhhhhh}x100]%1}",
                              "_X0_E_C_X1_Ehhhhhhhhhh_Fx100_D_M1_F"});

    auto function_type =
        llvm::FunctionType::get(array_type, {struct_type2}, false);

    kTestEntryList.push_back(
        {function_type, "(=0{[=1{hhhhhhhhhh}x100]%1}[%1x100])",
         "_A_X0_E_C_X1_Ehhhhhhhhhh_Fx100_D_M1_F_C_M1x100_D_B"});

    auto variadic_function_type =
        llvm::FunctionType::get(array_type, {struct_type2}, true);

    kTestEntryList.push_back(
        {variadic_function_type, "(=0{[=1{hhhhhhhhhh}x100]%1}&[%1x100])",
         "_A_X0_E_C_X1_Ehhhhhhhhhh_Fx100_D_M1_F_V_C_M1x100_D_B"});

      anvill::TypeDictionary type_dict(llvm_context);
      anvill::TypeTranslator specifier(type_dict, data_layout);

    for (const auto &test_entry : kTestEntryList) {
      auto without_alphanum = specifier.EncodeToString(test_entry.type, anvill::EncodingFormat::kDefault);
      auto with_alphanum = specifier.EncodeToString(test_entry.type, anvill::EncodingFormat::kValidSymbolCharsOnly);


      auto decoded_without_alphanum = specifier.DecodeFromString(test_entry.expected_non_alphanum_output);
      CHECK(decoded_without_alphanum.Succeeded());

      auto decoded_with_alphanum = specifier.DecodeFromString(test_entry.expected_alphanum_output);
      CHECK(decoded_with_alphanum.Succeeded());

      auto encoded_without_alphanum = specifier.EncodeToString(decoded_without_alphanum.TakeValue(), anvill::EncodingFormat::kDefault);
      auto encoded_with_alphanum = specifier.EncodeToString(decoded_with_alphanum.TakeValue(), anvill::EncodingFormat::kValidSymbolCharsOnly);

      CHECK_EQ(without_alphanum, encoded_without_alphanum);
      WARN_EQ(with_alphanum, encoded_with_alphanum);
    }

    //
    // These types should differ, just issue a warning for now
    //

    // variadic function vs non-variadic

    auto variadic_func_description =
        specifier.EncodeToString(variadic_function_type, anvill::EncodingFormat::kDefault);

    auto non_variadic_func_description =
        specifier.EncodeToString(function_type, anvill::EncodingFormat::kDefault);

    WARN_NE(variadic_func_description, non_variadic_func_description);

    auto variadic_alphanum_func_description =
        specifier.EncodeToString(variadic_function_type, anvill::EncodingFormat::kValidSymbolCharsOnly);

    auto non_variadic_alphanum_func_description =
        specifier.EncodeToString(function_type, anvill::EncodingFormat::kValidSymbolCharsOnly);

    WARN_NE(variadic_alphanum_func_description,
            non_variadic_alphanum_func_description);

    // packed struct vs non-packed
    std::vector<llvm::Type *> struct_part_list3 = {array_type, struct_type,
                                                   array_type, struct_type};

    auto non_packed_struct_type =
        llvm::StructType::create(struct_part_list3, "", false);

    auto packed_struct_type =
        llvm::StructType::create(struct_part_list3, "", true);

    auto non_packed_struct =
        specifier.EncodeToString(non_packed_struct_type,  anvill::EncodingFormat::kDefault);
    auto packed_struct = specifier.EncodeToString(packed_struct_type,  anvill::EncodingFormat::kDefault);

    WARN_NE(non_packed_struct, packed_struct);

    auto alphanum_non_packed_struct =
        specifier.EncodeToString(non_packed_struct_type, anvill::EncodingFormat::kValidSymbolCharsOnly);

    auto alphanum_packed_struct =
        specifier.EncodeToString(packed_struct_type, anvill::EncodingFormat::kValidSymbolCharsOnly);

    WARN_NE(alphanum_non_packed_struct, alphanum_packed_struct);
  }
  */

  TEST_CASE("Simple spec -> type -> spec roundtrip") {

    // Do not mark these as errors yet, as some of these tests
    // are not working

    const std::vector<std::pair<TypeSpec, const char *>> kTestSpecList = {
        {std::make_shared<FunctionType>(
             BaseType::Void,
             std::vector<TypeSpec>{
                 BaseType::Int32, BaseType::Int8,
                 std::make_shared<PointerType>(BaseType::Void, false),
                 BaseType::Int32},
             false),
         "void (i32, i8, ptr, i32)"},
        {BaseType::Int8, "i8"},
        {BaseType::Int16, "i16"},
        {BaseType::Int32, "i32"},
        {BaseType::Int64, "i64"},
        {BaseType::Float16, "half"},
        {std::make_shared<PointerType>(BaseType::Void, false), "ptr"},
    };

    llvm::LLVMContext llvm_context;
#if LLVM_VERSION_NUMBER < LLVM_VERSION(15, 0)
    llvm_context.enableOpaquePointers();
#endif
    llvm::Module module("TypeSpecifierTests", llvm_context);

    const auto &data_layout = module.getDataLayout();
    anvill::TypeDictionary type_dict(llvm_context);
    anvill::TypeTranslator specifier(type_dict, data_layout);

    for (auto [test_spec, ll_type] : kTestSpecList) {
      auto context_res = specifier.DecodeFromSpec(test_spec);
      REQUIRE(context_res.Succeeded());

      llvm::Type *type = context_res.TakeValue();

      std::string out;
      llvm::raw_string_ostream os(out);
      type->print(os);
      os.flush();

      REQUIRE(type != nullptr);
      auto ll_type_var = std::string(ll_type);
      REQUIRE(out == ll_type_var);
    }
  }
}

}  // namespace anvill
