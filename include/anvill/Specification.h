/*
 * Copyright (c) 2019-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "JSON.h"
#include "Result.h"

namespace llvm {
class BasicBlock;
class DataLayout;
class Function;
class FunctionType;
class GlobalVariable;
class Module;
class Type;
class Value;
namespace CallingConv {
using ID = unsigned;
}  // namespace CallingConv
namespace json {
class Object;
class Value;
}  // namespace json
}  // namespace llvm
namespace remill {
class Arch;
class IntrinsicTable;
struct Register;
}  // namespace remill
namespace anvill {

class SpecificationImpl;
class TypeDictionary;

// Represents the data pulled out of a JSON (sub-)program specification.
class Specification {
 private:
  Specification(void) = delete;

  std::shared_ptr<SpecificationImpl> impl;

  explicit Specification(std::shared_ptr<SpecificationImpl> impl_);

 public:
  ~Specification(void);

  // Try to create a program from a JSON specification. Returns a string error
  // if something went wrong.
  static anvill::Result<Specification, JSONDecodeError> DecodeFromJSON(
      const llvm::json::Value &val);

  // Try to encode the specification into JSON.
  anvill::Result<llvm::json::Object, JSONEncodeError> EncodeToJSON(void);
};

}  // namespace anvill
