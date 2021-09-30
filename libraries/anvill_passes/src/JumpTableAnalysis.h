#pragma once

#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>
#include <llvm/IR/ValueMap.h>
#include "IndirectJumpPass.h"


 namespace anvill {
    struct PcRel {
        private:
            llvm::ConstantInt* programCounter;
            llvm::IntegerType* expectedInputType;

        public:
            PcRel( llvm::ConstantInt* programCounter, llvm::IntegerType* expectedInputType): programCounter(programCounter), expectedInputType(expectedInputType) {

            }


            llvm::APInt apply(llvm::APInt loadedTableValue) {
                return this->programCounter->getValue() + loadedTableValue;
            }

            llvm::IntegerType* getExpectedType() {
                return this->expectedInputType;
            }

    };



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

    struct IndexRel {
        private:
            llvm::ConstantInt* jumpTableAddr;
            llvm::APInt optWordSize;
            llvm::ConstantInt* normalizer;
            llvm::Value* index;
            Cast cast;


        public: 
            IndexRel(llvm::ConstantInt* jumpTableAddr, llvm::Value* index, llvm::ConstantInt* normalizer, llvm::APInt optWordSize, Cast cast): jumpTableAddr(jumpTableAddr), optWordSize(optWordSize), normalizer(normalizer), index(index), cast(cast) {
                assert(this->index != nullptr);
            }

            llvm::APInt apply(llvm::APInt index) {
                return this->jumpTableAddr->getValue() + (this->cast.apply(this->normalizer->getValue() + index) * this->optWordSize);
            }

            llvm::APInt getMinimumIndex() {
                assert(this->normalizer->getValue().isNegative() );
                return (-this->normalizer->getValue());
            }
            
            llvm::Value* getIndex() {
                return this->index;
            }
    };





    struct JumpTableResult {
        PcRel pcRel;
        IndexRel indexRel;
        llvm::APInt upperBound;
        llvm::BasicBlock* defaultOut;


        llvm::APInt getIndexMinimimum();
            
    };

    class JumpTableAnalysis: public IndirectJumpPass<JumpTableAnalysis> {
            
            private:
                llvm::ValueMap<llvm::CallInst*, JumpTableResult> results;
            public:
                JumpTableAnalysis(): IndirectJumpPass()  {

                }

                llvm::StringRef getPassName() const override;

                void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
                bool runOnIndirectJump(llvm::CallInst* indirectJump);

                std::optional<JumpTableResult> getResultFor(llvm::CallInst* indirectJump) const;
        };
}
