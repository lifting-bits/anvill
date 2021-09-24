#pragma once

#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>


/*
The goal here is to lower anvill_complete_switch to an llvm switch when we can recover the cases. This analysis must be sound but anvill_complete_switch maybe used for any complete set of indirect targets
so cases may not even exist.

The analysis has to prove to us that this transformation is semantically preserving.

This pass focuses on lowering switch statements where a jumptable does exist

*/

namespace anvill {
    class SwitchLoweringPass: public llvm::FunctionPass{
        
        private:
            static char ID;
        public:
            SwitchLoweringPass() : llvm::FunctionPass(ID) {

            }


            llvm::StringRef getPassName() const override;

            void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
            bool runOnFunction(llvm::Function &F) override;
    };
}