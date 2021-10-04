#pragma once

#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>
#include "IndirectJumpPass.h"
#include <anvill/SliceManager.h>
/*
The goal here is to lower anvill_complete_switch to an llvm switch when we can recover the cases. This analysis must be sound but anvill_complete_switch maybe used for any complete set of indirect targets
so cases may not even exist.

The analysis has to prove to us that this transformation is semantically preserving.

This pass focuses on lowering switch statements where a jumptable does exist

*/

namespace anvill {
    class SwitchLoweringPass: public IndirectJumpPass<SwitchLoweringPass> {
        
        private:
            const std::shared_ptr<MemoryProvider> memProv;
            SliceManager& slm;
            
        public:
            SwitchLoweringPass(std::shared_ptr<MemoryProvider> memProv,  SliceManager& slm) : memProv(std::move(memProv)), slm(slm) {

            }

            llvm::StringRef getPassName() const override;

            void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;

            bool runOnIndirectJump(llvm::CallInst* indirectJump);
            
    };
}