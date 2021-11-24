#pragma once

#include <anvill/Lifter.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include <functional>
#include <memory>
#include <tuple>

#include "SliceInterpreter.h"

namespace anvill {

struct ClonedInstructions {
  llvm::ValueMap<llvm::Value *, llvm::Value *> mappingOldToNew;
  llvm::SmallVector<llvm::Instruction *> copied;
};

class SliceManager;
class SliceID {
  friend class SliceManager;

 private:
  uint64_t id;

  SliceID() : id(0) {}

  SliceID operator++(int) {
    auto temp = *this;
    this->id++;
    return temp;
  }
};
class SliceInterpreter;
class SliceManager {

 public:
  class Slice {
   private:
    // repr_function is an llvm function within the slice module that represents the slice with this ID. Non-constants/values not defined within the slice are
    // lifted to arguments for the function. The return value is the intended output of the slice for interpretation (generally the analysis target).
    llvm::Function *repr_function;
    SliceID id;
    // we need origin info for arguments somehow to basically allow analyses to get more context for the slice if they fail.
   public:
    Slice(llvm::Function *f, SliceID id) : repr_function(f), id(id) {}

    llvm::Function *getRepr() {
      return this->repr_function;
    }
  };


 protected:
  llvm::LLVMContext context;
  std::unique_ptr<llvm::Module> mod;
  std::optional<std::reference_wrapper<const EntityLifter>> lifter;

 private:
  // NOTE(ian): perhaps at some point we should split modules to prevent large numbers of slices in a single
  // module.

  SliceID next_id;
  std::map<uint64_t, Slice> slices;

  llvm::SmallVector<llvm::Instruction *>
  createMapperFromSlice(llvm::ArrayRef<llvm::Instruction *> slice,
                        llvm::ValueToValueMapTy &mapper);

  void insertClonedSliceIntoFunction(SliceID id, llvm::Function *targetFunc,
                                     llvm::Value *newRet,
                                     llvm::ArrayRef<llvm::Instruction *> slice);

  llvm::Function *
  createFunctionForCurrentID(SliceID id,
                             llvm::ArrayRef<llvm::Value *> arguments,
                             llvm::Value *returnVal);

  bool replaceGVsInUser(
      llvm::User *user,
      llvm::DenseMap<llvm::Constant *, llvm::Constant *> &to_replace);

  bool handleGV(llvm::GlobalVariable *gv, llvm::User *user,
                llvm::DenseMap<llvm::Constant *, llvm::Constant *> &to_replace);

  // returns true if succesful
  bool replaceAllGVConstantsWithInterpretableValue(
      llvm::ArrayRef<llvm::Instruction *> insn);

 public:
  static std::string getFunctionName(SliceID id) {
    return "sliceFunc." + std::to_string(id.id);
  }


  // Adds a slice of instructions to the slice manager. Any values not defined in the slice are lifted to arguments.
  // @slice The instructions in the slice
  // @param returnValue The value that will be returned from the slice.
  // @returns SliceID The id for retrieving the slice. If the return value is not defined in the slice the return value will be lifted to an argument.
  std::optional<SliceID> addSlice(llvm::ArrayRef<llvm::Instruction *> slice,
                                  llvm::Value *returnValue);


  Slice getSlice(SliceID id);

  SliceManager(const EntityLifter &lifter)
      : context(),
        mod(std::make_unique<llvm::Module>("slicemodule", this->context)),
        lifter({std::cref(lifter)}),
        next_id(SliceID()) {}

  SliceManager()
      : context(),
        mod(std::make_unique<llvm::Module>("slicemodule", this->context)),
        lifter(std::nullopt),
        next_id(SliceID()) {}

  ~SliceManager() {
    this->mod.reset();
  }

  SliceInterpreter getInterp();
};
}  // namespace anvill