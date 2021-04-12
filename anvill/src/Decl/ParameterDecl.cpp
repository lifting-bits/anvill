#include "ParameterDecl.h"

namespace anvill {

// Serialize a ParameterDecl to JSON
llvm::json::Object
ParameterDecl::SerializeToJSON(const llvm::DataLayout &dl) const {

  // Get the serialization for the ValueDecl
  llvm::json::Object param_json = this->ValueDecl::SerializeToJSON(dl);

  // Insert "name"
  param_json.insert(
      llvm::json::Object::KV{llvm::json::ObjectKey("name"), this->name});

  return param_json;
}

}