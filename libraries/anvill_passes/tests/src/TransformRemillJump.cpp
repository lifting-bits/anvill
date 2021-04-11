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

#include <anvill/Lifters/EntityLifter.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>

#include <iostream>

#include "Utils.h"

namespace anvill {

TEST_SUITE("TransformRemillJump") {
  TEST_CASE("Run the pass on function having _remill_jump as tail call") {
    llvm::LLVMContext llvm_context;
    auto module = LoadTestData(llvm_context, "TransformRemillJumpData.ll");

    auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                    remill::GetArchName("amd64"));
    REQUIRE(arch != nullptr);

    anvill::LifterOptions options(arch.get(), *module.get(), nullptr);

    // memory and types will not get used and create lifter with null
    anvill::EntityLifter lifter(options, nullptr, nullptr);

    CHECK(RunFunctionPass(module.get(),
                          CreateTransformRemillJumpIntrinsics(lifter)));

    REQUIRE(module->getFunction("__remill_jump") == nullptr);
  }
}

}  // namespace anvill
