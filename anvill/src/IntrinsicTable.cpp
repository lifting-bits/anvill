#include <anvill/IntrinsicTable.h>
#include <anvill/ABI.h>
#include <anvill/Decl.h>
#include <set>
#include <algorithm>
#include <anvill/Lifters/DeclLifter.h>

namespace anvill {
    void IntrinsicTable::RegisterBuilder(llvm::StringRef key,std::function<llvm::Function*()> builder) {
        this->lazy_intrinsic_builders.insert({key,builder});
    }

    llvm::Function* IntrinsicTable::GetIntrinsic(llvm::StringRef key) {

        if (this->target_module.getFunction(key) != nullptr) {
            return this->target_module.getFunction(key);
        }

        auto builder = this->lazy_intrinsic_builders.find(key);
        if (builder == this->lazy_intrinsic_builders.end()) {
            throw std::runtime_error("Requested unregistered intrinsic");
        }

        auto f = builder->second();
        this->target_module.getFunctionList().push_back(f);
        return f;
    }

    void AutoCaller::RegisterIntrinsic(llvm::StringRef key, std::vector<ValueDecl> params, std::vector<ValueDecl> rets) {
        std::vector<llvm::Type*> params_types;
        std::vector<llvm::Type*> ret_types;

        std::transform(params.begin(), params.end(), std::back_inserter(params_types), [](ValueDecl vdecl) {return vdecl.type;} );
        std::transform(rets.begin(), rets.end(), std::back_inserter(ret_types), [](ValueDecl vdecl) {return vdecl.type;} );


        // TODO(ian): need to refactor to wait for generating type until we have context
        auto ret_ty = llvm::StructType::create(ret_types,"return_type");
        auto func_ty = llvm::FunctionType::get(ret_ty, params_types, false);
        this->it_table.RegisterBuilder(key, [func_ty, key]() {
            return llvm::Function::Create(func_ty,llvm::GlobalValue::ExternalLinkage, key);
        });

        this->params.insert({key, params});
        this->returns.insert({key, rets});
    }

    void AutoCaller::InsertCall(llvm::BasicBlock *in_block, llvm::StringRef key, const remill::IntrinsicTable &intrinsics, llvm::Value *state_ptr,
                             llvm::Value *mem_ptr) {
            auto target_callee = this->it_table.GetIntrinsic(key);
            if (this->params.find(key) == this->params.end()) {
                throw std::runtime_error("Requested unregistered intrinsic");
            }

            auto params = this->params.find(key)->second;
            auto rets = this->returns.find(key)->second;


            std::vector<llvm::Value*> arg_values;
            for (auto par : params) {
                arg_values.push_back(LoadLiftedValue(par, intrinsics, in_block, state_ptr, mem_ptr));
            }

            llvm::IRBuilder<> ir(in_block);

            auto call_inst = ir.CreateCall(target_callee, arg_values);

            int i = 0;
            for (auto ret : rets) {
                auto extracted = ir.CreateExtractValue(call_inst,i);
                auto val = StoreNativeValue(extracted, ret, intrinsics, ir.GetInsertBlock(), state_ptr, mem_ptr);
                i++;
            }
    }
}