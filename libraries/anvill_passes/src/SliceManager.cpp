#include <anvill/SliceManager.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Operator.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include <exception>
#include <iostream>

namespace anvill {


llvm::Function *SliceManager::createFunctionForCurrentID(
    SliceID id, llvm::ArrayRef<llvm::Value *> arguments,
    llvm::Value *returnVal) {
  llvm::SmallVector<llvm::Type *> arg_types;
  std::transform(
      arguments.begin(), arguments.end(), std::back_inserter(arg_types),
      [](llvm::Value *arg) -> llvm::Type * { return arg->getType(); });
  llvm::FunctionType *ty =
      llvm::FunctionType::get(returnVal->getType(), arg_types, false);
  auto f = llvm::Function::Create(
      ty, llvm::GlobalValue::LinkageTypes::ExternalLinkage,
      SliceManager::getFunctionName(id), *this->mod);
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
    SliceID id, llvm::Function *targetFunc, llvm::Value *newReturn,
    llvm::ArrayRef<llvm::Instruction *> slice) {
  auto bb = llvm::BasicBlock::Create(targetFunc->getParent()->getContext(),
                                     "slicebasicblock." + std::to_string(id.id),
                                     targetFunc);

  std::for_each(slice.begin(), slice.end(), [bb](llvm::Instruction *insn) {
    bb->getInstList().push_back(insn);
  });


  llvm::ReturnInst::Create(targetFunc->getParent()->getContext(), newReturn,
                           bb);
  return;
}
bool SliceManager::handleGV(
    llvm::GlobalVariable *constant, llvm::User *user,
    llvm::DenseMap<llvm::Constant *, llvm::Constant *> &to_replace) {

  if (to_replace.find(llvm::cast<llvm::Constant>(user)) != to_replace.end()) {
    return true;
  }

  if (!constant->hasInitializer()) {
    if (auto *castIn = llvm::dyn_cast<llvm::PtrToIntOperator>(user)) {
      if (this->lifter.has_value()) {
        if (auto addr = this->lifter->get().AddressOfEntity(constant)) {
          auto intType = llvm::cast<llvm::IntegerType>(castIn->getType());
          to_replace.insert({llvm::cast<llvm::Constant>(castIn),
                             llvm::ConstantInt::get(intType, *addr)});

          return true;
        }
      }
    }

    return false;
  }

  return true;
}

bool SliceManager::replaceGVsInUser(
    llvm::User *user,
    llvm::DenseMap<llvm::Constant *, llvm::Constant *> &to_replace) {
  auto UE = user->op_end();
  for (auto UI = user->op_begin(); UI != UE; UI++) {
    if (auto *constant = llvm::dyn_cast<llvm::GlobalVariable>(UI->get())) {
      if (!this->handleGV(constant, UI->getUser(), to_replace)) {
        return false;
      }
    } else if (auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(UI->get())) {
      if (!this->replaceGVsInUser(CE, to_replace)) {
        return false;
      }
    }
  }

  return true;
}

bool SliceManager::replaceAllGVConstantsWithInterpretableValue(
    llvm::ArrayRef<llvm::Instruction *> insns) {

  llvm::DenseMap<llvm::Constant *, llvm::Constant *> remapper;
  for (auto insn : insns) {
    if (!this->replaceGVsInUser(insn, remapper)) {
      return false;
    }
  }

  for (auto ent : remapper) {

    ent.first->replaceAllUsesWith(ent.second);
    ent.first->destroyConstant();
  }

  return true;
}


std::optional<SliceID>
SliceManager::addSlice(llvm::ArrayRef<llvm::Instruction *> slice,
                       llvm::Value *returnValue) {
  auto id = this->next_id++;
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

  llvm::SmallVector<llvm::Value *> ordered_arguments(
      lifted_argument_set.begin(), lifted_argument_set.end());

  llvm::Function *slice_repr =
      this->createFunctionForCurrentID(id, ordered_arguments, returnValue);
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


  this->insertClonedSliceIntoFunction(id, slice_repr, new_ret, cloned);
  if (!this->replaceAllGVConstantsWithInterpretableValue(cloned)) {
    assert(false);
    slice_repr->eraseFromParent();
    return std::nullopt;
  }

  this->slices.insert({id.id, SliceManager::Slice(slice_repr, id)});
  return {id};
}

SliceManager::Slice SliceManager::getSlice(SliceID id) {
  return this->slices.find(id.id)->second;
}


SliceInterpreter SliceManager::getInterp() {
  return SliceInterpreter(*this->mod.get());
}
}  // namespace anvill