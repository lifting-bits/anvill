#pragma once
#include <anvill/Program.h>
#include <anvill/Decl.h>

namespace anvill {


    class FunctionPrototypeProvider {
        public:
            FunctionPrototypeProvider() {}
        

        void SetupProvider(const Program& prog);


        std::vector<ValueDecl> params;
        std::vector<ValueDecl> returns;
    };
}