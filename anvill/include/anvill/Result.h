/*
 * Copyright (c) 2021 Trail of Bits, Inc.
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

#pragma once

#include <stdexcept>
#include <variant>

namespace anvill {

template <typename ValueType, typename ErrorType>
class Result final {
 private:
  bool destroyed{true};
  mutable bool checked{false};
  std::variant<ValueType, ErrorType> data;

 public:
  Result();
  ~Result() = default;

  bool Succeeded() const;

  const ErrorType &Error() const;
  ErrorType TakeError();

  const ValueType &Value() const;
  ValueType TakeValue();

  const ValueType *operator->() const;

  Result(const ValueType &value);
  Result(ValueType &&value);

  Result(const ErrorType &error);
  Result(ErrorType &&error);

  Result(Result &&other) noexcept;
  Result &operator=(Result &&other) noexcept;

  Result(const Result &) = delete;
  Result &operator=(const Result &) = delete;

 private:
  void VerifyState() const;
  void VerifyChecked() const;
  void VerifyFailed() const;
  void VerifySucceeded() const;
};

template <typename ValueType, typename ErrorType>
Result<ValueType, ErrorType>::Result() {
  checked = true;
  data = ErrorType();
}

template <typename ValueType, typename ErrorType>
bool Result<ValueType, ErrorType>::Succeeded() const {
  VerifyState();

  checked = true;
  return std::holds_alternative<ValueType>(data);
}

template <typename ValueType, typename ErrorType>
const ErrorType &Result<ValueType, ErrorType>::Error() const {
  VerifyState();
  VerifyChecked();
  VerifyFailed();

  return std::get<ErrorType>(data);
}

template <typename ValueType, typename ErrorType>
ErrorType Result<ValueType, ErrorType>::TakeError() {
  VerifyState();
  VerifyChecked();
  VerifyFailed();

  auto error = std::move(std::get<ErrorType>(data));
  destroyed = true;

  return error;
}

template <typename ValueType, typename ErrorType>
const ValueType &Result<ValueType, ErrorType>::Value() const {
  VerifyState();
  VerifyChecked();
  VerifySucceeded();

  return std::get<ValueType>(data);
}

template <typename ValueType, typename ErrorType>
ValueType Result<ValueType, ErrorType>::TakeValue() {
  VerifyState();
  VerifyChecked();
  VerifySucceeded();

  auto value = std::move(std::get<ValueType>(data));
  destroyed = true;

  return value;
}

template <typename ValueType, typename ErrorType>
const ValueType *Result<ValueType, ErrorType>::operator->() const {
  return &Value();
}

template <typename ValueType, typename ErrorType>
Result<ValueType, ErrorType>::Result(const ValueType &value) {
  data = value;
  destroyed = false;
}

template <typename ValueType, typename ErrorType>
Result<ValueType, ErrorType>::Result(ValueType &&value) {
  data = std::move(value);
  destroyed = false;
}

template <typename ValueType, typename ErrorType>
Result<ValueType, ErrorType>::Result(const ErrorType &error) {
  data = error;
  destroyed = false;
}

template <typename ValueType, typename ErrorType>
Result<ValueType, ErrorType>::Result(ErrorType &&error) {
  data = std::move(error);
  destroyed = false;
}

template <typename ValueType, typename ErrorType>
Result<ValueType, ErrorType>::Result(Result &&other) noexcept {
  data = std::exchange(other.data, ErrorType());
  checked = std::exchange(other.checked, true);
  destroyed = std::exchange(other.destroyed, false);
}

template <typename ValueType, typename ErrorType>
Result<ValueType, ErrorType> &
Result<ValueType, ErrorType>::operator=(Result &&other) noexcept {
  if (this != &other) {
    data = std::exchange(other.data, ErrorType());
    checked = std::exchange(other.checked, true);
    destroyed = std::exchange(other.destroyed, false);
  }

  return *this;
}

template <typename ValueType, typename ErrorType>
void Result<ValueType, ErrorType>::VerifyState() const {
  if (!destroyed) {
    return;
  }

  throw std::logic_error(
      "The Result<ValueType, ErrorType> object no longer contains its internal data because it has been moved with TakeError/TakeValue");
}

template <typename ValueType, typename ErrorType>
void Result<ValueType, ErrorType>::VerifyChecked() const {
  if (checked) {
    return;
  }

  throw std::logic_error(
      "The Result<ValueType, ErrorType> object was not checked for success");
}

template <typename ValueType, typename ErrorType>
void Result<ValueType, ErrorType>::VerifySucceeded() const {
  if (std::holds_alternative<ValueType>(data)) {
    return;
  }

  throw std::logic_error(
      "The Result<ValueType, ErrorType> object has not succeeded");
}

template <typename ValueType, typename ErrorType>
void Result<ValueType, ErrorType>::VerifyFailed() const {
  if (std::holds_alternative<ErrorType>(data)) {
    return;
  }

  throw std::logic_error(
      "The Result<ValueType, ErrorType> object has not failed");
}

}  // namespace anvill
