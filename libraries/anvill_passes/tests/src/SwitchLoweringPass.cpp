#include <doctest.h>
#include <iostream>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Verifier.h>
#include "Utils.h"
#include <anvill/Transforms.h>
#include <llvm/IR/Dominators.h>



namespace anvill {

    namespace {
    
        llvm::Function* findFunction(llvm::Module* module) {
                for (auto &function : *module) {
                    if (function.getName().equals("sub_8240110__A_Sbi_Sbii_B_0")) {
                        return &function;
                    }
                }
                return nullptr;
        }
    }

    TEST_SUITE("SwitchLowerLargeFunction") {
    TEST_CASE("Run on large function") {
        llvm::LLVMContext context;
        auto mod = LoadTestData(context, "SwitchLoweringLarge.ll");
        auto targetFunction = findFunction(mod.get());
        CHECK(targetFunction != nullptr);
        llvm::legacy::FunctionPassManager fpm(mod.get());
        fpm.add(new llvm::DominatorTreeWrapperPass());
        fpm.add(CreateSwitchLoweringPass());
        fpm.doInitialization();
        fpm.run(*targetFunction);
        fpm.doFinalization();
    }
    }

}