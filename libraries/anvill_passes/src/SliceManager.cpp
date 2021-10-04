#include <llvm/ADT/SmallSet.h>
#include <exception>
#include <llvm/IR/GlobalValue.h>
#include <llvm/Transforms/Utils/ValueMapper.h> 
#include <llvm/IR/Instructions.h>
#include <anvill/SliceManager.h>
#include <iostream>

namespace anvill {


    llvm::Function* SliceManager::createFunctionForCurrentID(llvm::ArrayRef<llvm::Value*> arguments, llvm::Value* returnVal) {
        llvm::SmallVector<llvm::Type*> argTypes;
        std::transform(arguments.begin(), arguments.end(), std::back_inserter(argTypes), [](llvm::Value* arg) -> llvm::Type* {return arg->getType();});
        llvm::FunctionType* ty = llvm::FunctionType::get(returnVal->getType(),argTypes, false);
        return llvm::Function::Create(ty,llvm::GlobalValue::LinkageTypes::ExternalLinkage,this->getNextFunctionName(),*this->mod);
    }


    llvm::SmallVector<llvm::Instruction*> SliceManager::createMapperFromSlice(llvm::ArrayRef<llvm::Instruction*> slice, llvm::ValueToValueMapTy& mapper) {
        llvm::SmallVector<llvm::Instruction*> clonedInsns;

        std::for_each(slice.begin(),slice.end(),[&mapper,&clonedInsns](llvm::Instruction* insn) {
            auto cloned =  insn->clone();
            clonedInsns.push_back(cloned);
            mapper.insert({insn,cloned});
        });

        return clonedInsns;
    }

    void SliceManager::insertClonedSliceIntoFunction(llvm::Function* targetFunc, llvm::Value* newReturn, llvm::ArrayRef<llvm::Instruction*> slice) {
        auto bb = llvm::BasicBlock::Create(targetFunc->getParent()->getContext(),"slicebasicblock."+std::to_string(this->nextID.ID),targetFunc);
    
        std::for_each(slice.begin(), slice.end(),   [bb](llvm::Instruction* insn) { bb->getInstList().push_back(insn);});
        llvm::ReturnInst::Create(targetFunc->getParent()->getContext(),newReturn,bb);
        return;
    }

llvm::Twine SliceManager::getNextFunctionName() {
    return SliceManager::getFunctionName(this->nextID);
}


    SliceID SliceManager::addSlice(llvm::ArrayRef<llvm::Instruction*> slice, llvm::Value* returnValue) {
        auto id = this->nextID;
        llvm::SmallDenseSet<llvm::Value*> definedValue;
        for (auto insn : slice) {
            definedValue.insert(insn);
        }
        
        llvm::SmallDenseSet<llvm::Value*> liftedArgumentSet;
        for (auto insn : slice) {
            for (const auto& use : insn->operands()) {

                if (definedValue.find(use.get()) == definedValue.end() && !llvm::isa<llvm::Constant>(use.get())) {
                    liftedArgumentSet.insert(use.get());
                }
            }
        }

        if (definedValue.find(returnValue) == definedValue.end()) {
            liftedArgumentSet.insert(returnValue);
        }

        llvm::SmallVector<llvm::Value*> orderedArguments(liftedArgumentSet.begin(), liftedArgumentSet.end());

        llvm::Function* sliceRepr = this->createFunctionForCurrentID(orderedArguments, returnValue);
        llvm::ValueToValueMapTy mapper;
        auto cloned = this->createMapperFromSlice(slice, mapper);

        auto i = 0;
        for (auto liftedArg : orderedArguments) {
            auto arg = sliceRepr->getArg(i);
            mapper.insert({liftedArg,arg});
            i++;
        }

        std::for_each(cloned.begin(), cloned.end(), [&mapper](llvm::Instruction* insn) {
            llvm::RemapInstruction(insn, mapper);
        } );

        auto newRet = mapper[returnValue];

        this->insertClonedSliceIntoFunction(sliceRepr, newRet, cloned);
        this->slices.insert({this->nextID.ID, SliceManager::Slice(sliceRepr,this->nextID)});

        this->nextID++;
        return id;
    }

      SliceManager::Slice SliceManager::getSlice(SliceID id) {
          SliceManager::Slice sl = this->slices.find(id.ID)->second;
          return sl;
      }


    SliceInterpreter SliceManager::getInterp() {
        return SliceInterpreter(*this->mod.get());
     }
}