#include <anvill/SliceManager.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include <exception>
#include <iostream>

namespace anvill {


llvm::Function *SliceManager::createFunctionForCurrentID(
    llvm::ArrayRef<llvm::Value *> arguments, llvm::Value *returnVal) {
  llvm::SmallVector<llvm::Type *> arg_types;
  std::transform(
      arguments.begin(), arguments.end(), std::back_inserter(arg_types),
      [](llvm::Value *arg) -> llvm::Type * { return arg->getType(); });
  llvm::FunctionType *ty =
      llvm::FunctionType::get(returnVal->getType(), arg_types, false);
  auto f = llvm::Function::Create(
      ty, llvm::GlobalValue::LinkageTypes::ExternalLinkage,
      this->getNextFunctionName(), *this->mod);
  return f;
}


llvm::SmallVector<llvm::Instruction *>
SliceManager::createMapperFromSlice(llvm::ArrayRef<llvm::Instruction *> slice,
                                    llvm::ValueToValueMapTy &mapper) {
  llvm::SmallVector<llvm::Instruction *> cloned_insns;

  std::for_each(slice.begin(), slice.end(),
                [&mapper, &cloned_insns](llvm::Instruction *insn) {
                  auto cloned = insn->clone();
                  cloned_insns.push_back(cloned);
                  mapper.insert({insn, cloned});
                });

  return cloned_insns;
}

void SliceManager::insertClonedSliceIntoFunction(
    llvm::Function *targetFunc, llvm::Value *newReturn,
    llvm::ArrayRef<llvm::Instruction *> slice) {
  auto bb = llvm::BasicBlock::Create(
      targetFunc->getParent()->getContext(),
      "slicebasicblock." + std::to_string(this->next_id.id), targetFunc);

  std::for_each(slice.begin(), slice.end(), [bb](llvm::Instruction *insn) {
    bb->getInstList().push_back(insn);
  });


  llvm::ReturnInst::Create(targetFunc->getParent()->getContext(), newReturn,
                           bb);

  return;
}

std::string SliceManager::getNextFunctionName() {
  return SliceManager::getFunctionName(this->next_id);
}


SliceID SliceManager::addSlice(llvm::ArrayRef<llvm::Instruction *> slice,
                               llvm::Value *returnValue) {
  auto id = this->next_id;
  llvm::SmallDenseSet<llvm::Value *> defined_value;
  for (auto insn : slice) {
    defined_value.insert(insn);
  }

  llvm::SmallDenseSet<llvm::Value *> lifted_argument_set;
  for (auto insn : slice) {
    for (const auto &use : insn->operands()) {

      if (defined_value.find(use.get()) == defined_value.end() &&
          !llvm::isa<llvm::Constant>(use.get())) {
        lifted_argument_set.insert(use.get());
      }
    }
  }

  if (defined_value.find(returnValue) == defined_value.end()) {
    lifted_argument_set.insert(returnValue);
  }

  llvm::SmallVector<llvm::Value *> ordered_arguments(lifted_argument_set.begin(),
                                                    lifted_argument_set.end());

  llvm::Function *slice_repr =
      this->createFunctionForCurrentID(ordered_arguments, returnValue);
  llvm::ValueToValueMapTy mapper;
  auto cloned = this->createMapperFromSlice(slice, mapper);

  auto i = 0;
  for (auto lifted_arg : ordered_arguments) {
    auto arg = slice_repr->getArg(i);
    mapper.insert({lifted_arg, arg});
    i++;
  }

  std::for_each(cloned.begin(), cloned.end(),
                [&mapper](llvm::Instruction *insn) {
                  llvm::RemapInstruction(insn, mapper);
                });

  auto new_ret = mapper[returnValue];

  this->insertClonedSliceIntoFunction(slice_repr, new_ret, cloned);
  this->slices.insert(
      {this->next_id.id, SliceManager::Slice(slice_repr, this->next_id)});

  this->next_id++;
  return id;
}

SliceManager::Slice SliceManager::getSlice(SliceID id) {
  SliceManager::Slice sl = this->slices.find(id.id)->second;
  return sl;
}


SliceInterpreter SliceManager::getInterp() {
  return SliceInterpreter(*this->mod.get());
}
}  // namespace anvill