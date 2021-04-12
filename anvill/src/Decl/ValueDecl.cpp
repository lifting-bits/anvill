#include "ValueDecl.h"

#include <glog/logging.h>
#include <llvm_utils/TypePrinter.h>

namespace anvill {

// Serialize a ValueDecl to JSON
llvm::json::Object
ValueDecl::SerializeToJSON(const llvm::DataLayout &dl) const {
  llvm::json::Object value_json;

  if (reg) {

    // The value is in a register
    value_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("register"), reg->name});
  } else if (mem_reg) {

    // The value is in memory
    llvm::json::Object memory_json;
    memory_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("register"),
                                              mem_reg->name});
    memory_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("offset"), mem_offset});

    // Wrap the memory_json structure in a memory block
    value_json.insert(
        llvm::json::Object::KV{llvm::json::ObjectKey("memory"),
                               llvm::json::Value(std::move(memory_json))});
  } else {
    LOG(FATAL) << "Trying to serialize a value that has not been allocated";
  }

  value_json.insert(llvm::json::Object::KV{llvm::json::ObjectKey("type"),
                                           llvm_utils::TranslateType(*type, dl)});

  return value_json;
}

}