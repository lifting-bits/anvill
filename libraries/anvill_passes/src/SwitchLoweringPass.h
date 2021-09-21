#pragma once

#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>


class SwitchLoweringPass: public llvm::FunctionPass{
    static char ID;
    SwitchLoweringPass() : llvm::FunctionPass(ID) {

    }

    bool runOnFunction(llvm::Function &F) override;
};