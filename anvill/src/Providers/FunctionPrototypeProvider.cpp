#include <anvill/Providers/FunctionPrototypeProvider.h>
#include <set>

namespace anvill {
    namespace {
        struct compare_value_decls {
            bool operator()(anvill::ValueDecl a, anvill::ValueDecl b) const {
                return (a.mem_reg != nullptr && b.reg != nullptr) 
                    || (a.mem_reg != nullptr && b.mem_reg != nullptr && a.mem_offset < b.mem_offset && a.mem_reg->name < b.mem_reg->name)
                    || (a.reg != nullptr && b.reg != nullptr && a.reg < b.reg);
            }
        };

    }


    void FunctionPrototypeProvider::SetupProvider(const Program& prog) {
              // TODO(ian): Handle overlapping decls

        std::set<ValueDecl, compare_value_decls> params;
        std::set<ValueDecl, compare_value_decls> rets;
        prog.ForEachFunction([&params, &rets] (const FunctionDecl* fdecl) {
            for (auto p : fdecl->params) {
                params.insert(p);
            }

            for (auto r: fdecl->returns) {
                rets.insert(r);
            }

            return true;
            });
        
        for (auto x : params) {
            this->params.push_back(x);
        }

        for (auto x: rets) {
            this->returns.push_back(x);
        }
    }
}