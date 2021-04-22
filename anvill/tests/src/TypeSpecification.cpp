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

#include <vector>

namespace anvill {

TEST_SUITE("TypeSpecification") {
  TEST_CASE("Basic tests") {
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
}

}  // namespace anvill
