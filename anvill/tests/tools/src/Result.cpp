/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Result.h>
#include <doctest.h>
#include <variant>
#include <memory>

namespace anvill {

namespace {

std::size_t deleter_invocation_count{0U};

struct UniquePtrDeleter final {
  void operator()(void *ptr) const {
    if (ptr != nullptr) {
      ++deleter_invocation_count;
    }
  }
};

void *kTestPointer{reinterpret_cast<void *>(1)};

using UniquePtr = std::unique_ptr<void, UniquePtrDeleter>;

enum class TestErrorCode {
  ErrorCode,
};

using UniquePtrResult = Result<UniquePtr, TestErrorCode>;
using SuccessOrTestErrorCode = Result<std::monostate, TestErrorCode>;

}  // namespace

TEST_SUITE("Result") {
  TEST_CASE("Must not be copyable") {
    REQUIRE(std::is_copy_constructible<SuccessOrTestErrorCode>::value == 0);

    REQUIRE(
        std::is_trivially_copy_constructible<SuccessOrTestErrorCode>::value ==
        0);

    REQUIRE(std::is_nothrow_copy_constructible<SuccessOrTestErrorCode>::value ==
            0);

    REQUIRE(std::is_copy_assignable<SuccessOrTestErrorCode>::value == 0);

    REQUIRE(std::is_trivially_copy_assignable<SuccessOrTestErrorCode>::value ==
            0);

    REQUIRE(std::is_nothrow_copy_assignable<SuccessOrTestErrorCode>::value ==
            0);
  }

  TEST_CASE("Self-test") {
    deleter_invocation_count = 0U;

    {
      UniquePtr unique_ptr;
      unique_ptr.reset(kTestPointer);
    }

    REQUIRE(deleter_invocation_count == 1U);
  }

  TEST_CASE("Sanity checks") {

    // Create a new Result object; we should not be able to
    // use it yet because it's not set
    UniquePtrResult result;

    bool exception_thrown{false};
    try {
      result.Succeeded();
    } catch (...) {
      exception_thrown = true;
    }

    CHECK(exception_thrown);

    // Set a value in the Result object
    deleter_invocation_count = 0U;

    UniquePtr non_copyable_value;
    non_copyable_value.reset(kTestPointer);

    result = std::move(non_copyable_value);
    REQUIRE(deleter_invocation_count == 0U);

    // This should now qualify as succeeded
    REQUIRE(result.Succeeded());

    // We should be able to reference the value multiple times
    // if we do not take it out of the Result object
    result.Value().get();
    result.Value().get();
    result.Value().get();

    // If we take the value however, it will get destroyed
    // once it goes out of scope
    {
      auto restored_value = result.TakeValue();
      REQUIRE(deleter_invocation_count == 0U);
      REQUIRE(restored_value.get() == kTestPointer);
    }

    REQUIRE(deleter_invocation_count == 1U);

    // We should no longer be able to use the Result object, because
    // it needs to be reset
    exception_thrown = false;

    try {
      auto restored_value = result.TakeValue();
    } catch (...) {
      exception_thrown = true;
    }

    CHECK(exception_thrown);

    // Set a new value again into the result object and then try to
    // move it
    non_copyable_value.reset(kTestPointer);
    result = std::move(non_copyable_value);

    {
      UniquePtrResult result2;
      result2 = std::move(result);

      REQUIRE(deleter_invocation_count == 1U);
    }

    REQUIRE(deleter_invocation_count == 2U);

    // The original object should no longer be usable
    exception_thrown = false;

    try {
      auto restored_value = result.TakeValue();
    } catch (...) {
      exception_thrown = true;
    }

    CHECK(exception_thrown);

    // We should get an exception if we try to access the value or
    // the error without checking for success first
    non_copyable_value.reset(kTestPointer);
    result = std::move(non_copyable_value);

    exception_thrown = false;

    try {
      result.Value();
    } catch (...) {
      exception_thrown = true;
    }

    CHECK(exception_thrown);

    exception_thrown = false;

    try {
      result.Error();
    } catch (...) {
      exception_thrown = true;
    }

    CHECK(exception_thrown);
  }
}

}  // namespace anvill
