/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <iostream>

#include <anvill/Passes/TransformRemillJumpIntrinsics.h>
#include <anvill/CrossReferenceResolver.h>
#include "Utils.h"

namespace anvill {

TEST_SUITE("TransformRemillJump_Test0") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    auto llvm_context = anvill::CreateContextWithOpaquePointers();
    auto module = LoadTestData(*llvm_context, "TransformRemillJumpData0.ll");

    auto arch =
        remill::Arch::Build(llvm_context.get(), remill::GetOSName("linux"),
                            remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

      auto ctrl_flow_provider =
          anvill::NullControlFlowProvider();
      TypeDictionary tyDict(*llvm_context);

      NullTypeProvider ty_prov(tyDict);
      NullMemoryProvider mem_prov;
      anvill::LifterOptions lift_options(
          arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

    anvill::LifterOptions options(arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options);

    EntityCrossReferenceResolver xref(lifter);

    CHECK(RunFunctionPass(module.get(), TransformRemillJumpIntrinsics(xref)));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");

    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_Test1") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    auto llvm_context = anvill::CreateContextWithOpaquePointers();
    auto module = LoadTestData(*llvm_context, "TransformRemillJumpData1.ll");

    auto arch =
        remill::Arch::Build(llvm_context.get(), remill::GetOSName("linux"),
                            remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);
      auto ctrl_flow_provider =
          anvill::NullControlFlowProvider();
      TypeDictionary tyDict(*llvm_context);

      NullTypeProvider ty_prov(tyDict);
      NullMemoryProvider mem_prov;
      anvill::LifterOptions lift_options(
          arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

    anvill::LifterOptions options(arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options);

    EntityCrossReferenceResolver xref(lifter);

    CHECK(RunFunctionPass(module.get(), TransformRemillJumpIntrinsics(xref)));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_ARM32_0") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    auto llvm_context = anvill::CreateContextWithOpaquePointers();
    auto module =
        LoadTestData(*llvm_context, "TransformRemillJumpDataARM32_0.ll");

    auto arch =
        remill::Arch::Build(llvm_context.get(), remill::GetOSName("linux"),
                            remill::GetArchName("aarch32"));
    REQUIRE(arch != nullptr);

    auto ctrl_flow_provider = anvill::NullControlFlowProvider();
    TypeDictionary tyDict(*llvm_context);

    NullTypeProvider ty_prov(tyDict);
    NullMemoryProvider mem_prov;
    anvill::LifterOptions lift_options(arch.get(), *module, ty_prov,
                                       std::move(ctrl_flow_provider), mem_prov);

    anvill::LifterOptions options(arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options);

    EntityCrossReferenceResolver xref(lifter);

    CHECK(RunFunctionPass(module.get(), TransformRemillJumpIntrinsics(xref)));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

TEST_SUITE("TransformRemillJump_ARM32_1") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    auto llvm_context = anvill::CreateContextWithOpaquePointers();
    auto module =
        LoadTestData(*llvm_context, "TransformRemillJumpDataARM32_1.ll");

    auto arch =
        remill::Arch::Build(llvm_context.get(), remill::GetOSName("linux"),
                            remill::GetArchName("aarch32"));
    REQUIRE(arch != nullptr);

    auto ctrl_flow_provider = anvill::NullControlFlowProvider();
    TypeDictionary tyDict(*llvm_context);

    NullTypeProvider ty_prov(tyDict);
    NullMemoryProvider mem_prov;
    anvill::LifterOptions lift_options(arch.get(), *module, ty_prov,
                                       std::move(ctrl_flow_provider), mem_prov);

    anvill::LifterOptions options(arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options);

    EntityCrossReferenceResolver xref(lifter);

    CHECK(RunFunctionPass(module.get(), TransformRemillJumpIntrinsics(xref)));

    const auto ret_func = module->getFunction("__remill_function_return");
    const auto jmp_func = module->getFunction("__remill_jump");


    REQUIRE((ret_func && !ret_func->use_empty()));
    REQUIRE((!jmp_func || jmp_func->use_empty()));
  }
}

}  // namespace anvill
