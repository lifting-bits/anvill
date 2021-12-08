#pragma once

#include <llvm/ADT/StringMap.h>
#include <llvm/IR/Function.h>
#include <anvill/Program.h>
#include <anvill/Decl.h>

namespace anvill {


    class IntrinsicTable {
        private:
            llvm::StringMap<std::function<llvm::Function*()>> lazy_intrinsic_builders;
            llvm::Module& target_module;
        public:
            IntrinsicTable( llvm::Module& target_module): target_module(target_module) {}

            void SetupHostModule(llvm::Module* mod);

            void RegisterBuilder(llvm::StringRef key,std::function<llvm::Function*()> builder);

            llvm::Function* GetIntrinsic(llvm::StringRef key);
    };

    // Wraps an intrinsic table and allows intrinsics to be registered that can be automatically called by copying addressable values from the state
    class AutoCaller {
        private: 
            IntrinsicTable it_table;
            llvm::StringMap<std::vector<ValueDecl>> params;
            llvm::StringMap<std::vector<ValueDecl>> returns;
        public:
            AutoCaller(llvm::Module& target_module): it_table(target_module) {}

            void RegisterIntrinsic(llvm::StringRef key, std::vector<ValueDecl> param, std::vector<ValueDecl> returns);

            // adds instructions to in_block to load the parameters, call the intrinsic, and store the returns back into the target locations
            void InsertCall(llvm::BasicBlock *in_block, llvm::StringRef key, const remill::IntrinsicTable &intrinsics, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr);
    };


    AutoCaller BuildAutoCaller(const  Program& prog);
}