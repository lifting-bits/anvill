#pragma once

#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>
#include <anvill/ABI.h>

namespace anvill {
    namespace {
        bool isTargetInstrinsic(const llvm::CallInst* callinsn) {
            if (const auto *callee = callinsn->getCalledFunction()) {
                return callee->getName().equals(kAnvillSwitchCompleteFunc);
            }

            return false;
        }

        std::vector<llvm::CallInst*> getTargetCalls(llvm::Function &F) {
            std::vector<llvm::CallInst*> calls;
            for ( auto& blk: F.getBasicBlockList()) {
                for( auto& insn: blk.getInstList()) {
                    llvm::Instruction* new_insn = &insn;
                    if ( llvm::CallInst* call_insn = llvm::dyn_cast<llvm::CallInst>(new_insn)) {
                        if(isTargetInstrinsic(call_insn)) {
                            calls.push_back(call_insn);
                        }
                    }
                }
            }
            return calls;
        }
    }

    // (ian) Unfortunately pretty sure CRTP is the only way to do this without running into issues with pass IDs
    template <typename UserFunctionPass>
    class IndirectJumpPass: public llvm::FunctionPass {
        public:
            static char ID;

            IndirectJumpPass(): llvm::FunctionPass(ID) {

            }

            virtual bool runOnFunction(llvm::Function &F) override;
    };


    template<typename UserFunctionPass> 
    char  IndirectJumpPass<UserFunctionPass>::ID = '\0';

    template<typename UserFunctionPass> bool IndirectJumpPass<UserFunctionPass>::runOnFunction(llvm::Function &F) {
        auto &function_pass = *static_cast<UserFunctionPass *>(this);
        bool isModified = false;
        for(auto targetCall : getTargetCalls(F)) {
            isModified |= function_pass.runOnIndirectJump(targetCall);
        }

        return isModified; 
    }
}