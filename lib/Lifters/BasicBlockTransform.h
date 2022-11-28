
#include <anvill/Declarations.h>
#include <anvill/Specification.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>

#include <vector>
namespace anvill {

struct AnvillBasicBlock {
  llvm::Function *basic_block_repr_func;
  const BasicBlockContext &context;
};


struct Transformed {
  llvm::Function *new_func;
  std::vector<ParameterDecl> appended_args;
};

class BasicBlockTransform {
 public:
  BasicBlockTransform(const TypeDictionary &types,
                      const remill::IntrinsicTable &intrinsics)
      : types(types),
        intrinsics(intrinsics) {}

 public:
  virtual Transformed Transform(const AnvillBasicBlock &bb);

 protected:
  virtual Transformed TransformInternal(const AnvillBasicBlock &bb) {
    return {bb.basic_block_repr_func, {}};
  };

  const TypeDictionary &types;
  const remill::IntrinsicTable &intrinsics;
};


class CallAndInitializeParameters : public BasicBlockTransform {
 protected:
  virtual Transformed TransformInternal(const AnvillBasicBlock &bb);

 public:
  CallAndInitializeParameters(const TypeDictionary &types,
                              const remill::IntrinsicTable &intrinsics)
      : BasicBlockTransform(types, intrinsics) {}
};
}  // namespace anvill