#include <anvill/Transforms.h>
#include "SwitchLoweringPass.h"
#include <anvill/ABI.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/PatternMatch.h>
#include <iostream>
#include <llvm/IR/Dominators.h>
#include <llvm/Pass.h>
#include <llvm/IR/DerivedUser.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/InstVisitor.h>
#include <optional>
#include <memory>
#include <numeric>
#include <unordered_set>
#include <unordered_map>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <anvill/IndirectJumpPass.h>
#include <anvill/JumpTableAnalysis.h>

namespace anvill {

    class PcBinding {
        private:
            llvm::DenseMap<llvm::APInt, llvm::BasicBlock*> mapping;

            PcBinding(llvm::DenseMap<llvm::APInt, llvm::BasicBlock*> mapping): mapping(std::move(mapping)) {

            }


        public: 
            
            std::optional<llvm::BasicBlock*> lookup(llvm::APInt targetPc) const {
                if (this->mapping.find(targetPc) != this->mapping.end()) {
                    return {this->mapping.find(targetPc)->second};
                }

                return std::nullopt;
            }
            
            static PcBinding build(const llvm::CallInst* complete_switch, llvm::SwitchInst* follower) {
                assert(complete_switch->getNumArgOperands()-1==follower->getNumCases());

                llvm::DenseMap<llvm::APInt, llvm::BasicBlock*> mapping;
                for (auto caseHandler: follower->cases()) {
                    auto pcArg = complete_switch->getArgOperand(caseHandler.getCaseValue()->getValue().getLimitedValue()+1);// is the switch has more than 2^64 cases we have bigger problems
                    mapping.insert({llvm::cast<llvm::ConstantInt>(pcArg)->getValue(),caseHandler.getCaseSuccessor()});//  the argument to a complete switch should always be a constant int
                }

               return PcBinding(std::move(mapping));
            }
    };

   

    void SwitchLoweringPass::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
        AU.setPreservesCFG(); // (ian) TODO in the future this will need to get removed when we eliminate the branch for table range checking.
        AU.addRequired<JumpTableAnalysis>();
    
    }



    class SwitchBuilder {
    private:
        llvm::LLVMContext& context;
        SliceManager& slm;
        const std::shared_ptr<MemoryProvider>& memProv;
        const llvm::DataLayout& dl;

        std::optional<llvm::APInt> readIntFrom(llvm::IntegerType* ty, llvm::APInt addr) {
            auto uaddr = addr.getLimitedValue();
            std::vector<uint8_t> memory;
            assert(ty->getBitWidth() % 8 == 0);
            auto target_bytes = ty->getBitWidth()/8;

            for (uint64_t i = 0; i < target_bytes; i++) {
                auto res = this->memProv->Query(uaddr+i);
                ByteAvailability avail = std::get<1>(res);
                if(avail != ByteAvailability::kAvailable) {
                    return std::nullopt;
                }
            
                memory.push_back(std::get<0>(res));
            }


            llvm::APInt res(ty->getBitWidth(), 0);


            // Endianess? may have to flip around memory as needed, yeah looks like LoadIntMemory loads at system memory so need to use flip_memory in llvm::endianess
            llvm::LoadIntFromMemory(res,memory.data(),target_bytes);

            if (this->dl.isLittleEndian() == llvm::sys::IsLittleEndianHost) {
                return res;
            } else {
                return res.byteSwap();
            }
        }
    public:
        SwitchBuilder(llvm::LLVMContext& context, SliceManager& slm,const std::shared_ptr<MemoryProvider>& memProv, const llvm::DataLayout& dl): context(context), slm(slm), memProv(memProv), dl(dl) {

        }

        std::optional<llvm::SwitchInst*> createNativeSwitch( JumpTableResult jt, const PcBinding& binding, llvm::LLVMContext& context) {
            auto minIndex = jt.lowerBound;
            auto numberOfCases = (jt.upperBound-minIndex) + 1;
            auto interp = this->slm.getInterp();
            llvm::SwitchInst* newSwitch = llvm::SwitchInst::Create(jt.indexRel.getIndex(),jt.defaultOut,numberOfCases.getLimitedValue());
            for(llvm::APInt currIndValue = minIndex; currIndValue.ule(jt.upperBound); currIndValue+=1) {
                auto readAddress = jt.indexRel.apply(interp,currIndValue);
                std::optional<llvm::APInt> jmpOff = this->readIntFrom(jt.pcRel.getExpectedType(slm),readAddress);
                if (!jmpOff.has_value()) {
                    delete newSwitch;
                    return std::nullopt;
                } 

                auto newPc = jt.pcRel.apply(interp,*jmpOff);
                auto outBlock = binding.lookup(newPc);
                if (!outBlock.has_value()) {
                    delete newSwitch;
                    return std::nullopt;
                } 


                if (*outBlock != jt.defaultOut) {
                    llvm::ConstantInt* indexVal = llvm::ConstantInt::get(this->context, currIndValue);
                    newSwitch->addCase(indexVal,*outBlock);  
                }
            }
            return newSwitch;
        }
    };


     bool SwitchLoweringPass::runOnIndirectJump(llvm::CallInst* targetCall) {


    
        const auto& jtAnalysis = this->getAnalysis<JumpTableAnalysis>();
        auto jresult = jtAnalysis.getResultFor(targetCall);


        if (!jresult.has_value()) {
            return false;
        }

        llvm::Function& F = *targetCall->getFunction();
        auto dl = F.getParent()->getDataLayout();
        llvm::LLVMContext& context = F.getParent()->getContext();

        SwitchBuilder sbuilder(context, this->slm, this->memProv, dl);
        auto followingSwitch = targetCall->getParent()->getTerminator();
        auto follower = llvm::cast<llvm::SwitchInst>(followingSwitch);
        auto binding = PcBinding::build(targetCall, follower); 
        std::optional<llvm::SwitchInst*> newSwitch = sbuilder.createNativeSwitch(*jresult,binding,context);

        if (newSwitch) {
            llvm::ReplaceInstWithInst(follower, *newSwitch);
            return true;
        }

        return false;
     }


    llvm::FunctionPass* CreateSwitchLoweringPass(const std::shared_ptr<MemoryProvider>& memProv, SliceManager& slm) {
        return new SwitchLoweringPass(memProv, slm);
    }

    llvm::StringRef SwitchLoweringPass::getPassName() const {
        return "SwitchLoweringPass";
    }

}