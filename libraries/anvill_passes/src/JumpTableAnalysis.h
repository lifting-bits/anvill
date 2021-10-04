#pragma once

#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>
#include <llvm/IR/ValueMap.h>
#include "IndirectJumpPass.h"
#include <anvill/SliceManager.h>

 namespace anvill {

    enum CastType {ZEXT, SEXT, NONE};
    struct Cast {
        CastType caTy;
        unsigned int toBits;

        llvm::APInt apply(llvm::APInt target) {
            switch(this->caTy) {
                case CastType::ZEXT:
                    return target.zext(this->toBits);
                case CastType::SEXT:
                    return target.sext(this->toBits);
                case CastType::NONE:
                    return target;
            }
        }
    };


    class PcRel {
        public:
            PcRel(SliceManager::SliceID slice): slice(slice) {

            }

            llvm::APInt apply(llvm::APInt loadedVal);


            llvm::IntegerType* getExpectedType();
            
        private:
            SliceManager::SliceID  slice;
    };


    class IndexRel {
        private:
            SliceManager::SliceID  slice;
            llvm::Value* index;
        public:
            llvm::Value* getIndex();
            llvm::APInt apply(llvm::APInt indexValue);

            IndexRel(SliceManager::SliceID slice, llvm::Value* index): slice(slice), index(index) {

            }
    };


    struct JumpTableResult {
        PcRel  pcRel;
        IndexRel indexRel;
        llvm::APInt upperBound; // exclustive
        llvm::APInt lowerBound; // inclusive
        llvm::BasicBlock* defaultOut;

    };

    class JumpTableAnalysis: public IndirectJumpPass<JumpTableAnalysis> {
            
            private:
                SliceManager& slices;
                llvm::ValueMap<llvm::CallInst*, JumpTableResult> results;
            public:
                JumpTableAnalysis(SliceManager& slices): IndirectJumpPass(), slices(slices)  {

                }

                llvm::StringRef getPassName() const override;

                void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
                bool runOnIndirectJump(llvm::CallInst* indirectJump);

                std::optional<JumpTableResult> getResultFor(llvm::CallInst* indirectJump) const;
        };
}
