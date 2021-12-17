#include <anvill/Lifters.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/IR/Verifier.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include <anvill/Lifters.h>
#include <anvill/Providers.h>
#include <iostream>

#include <anvill/Passes/ConvertAddressesToEntityUses.h>
#include <anvill/CrossReferenceResolver.h>
#include "Utils.h"

namespace anvill {

    TEST_SUITE("RecoverEntityUses") {
    TEST_CASE("Regression test for unresolved anvill_pc") {
        llvm::LLVMContext llvm_context;
        auto module = LoadTestData(llvm_context, "TestingUnresolvedEntity.ll");
        

        auto arch = remill::Arch::Build(&llvm_context, remill::GetOSName("linux"),
                                        remill::GetArchName("amd64"));
        REQUIRE(arch != nullptr);

        auto ctrl_flow_provider =
            anvill::NullControlFlowProvider();
        TypeDictionary tyDict(llvm_context);

        NullTypeProvider ty_prov(tyDict);
        NullMemoryProvider mem_prov;
        anvill::LifterOptions lift_options(
            arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

        anvill::LifterOptions options(arch.get(), *module,ty_prov,std::move(ctrl_flow_provider),mem_prov);

        // memory and types will not get used and create lifter with null
        anvill::EntityLifter lifter(options);

        EntityCrossReferenceResolver xref(lifter);

        ConvertAddressesToEntityUses conv(xref);

        auto func = module->getFunction("sub_12b30__A_SBI_B_0.6");

        REQUIRE(func != nullptr);
        
        llvm::FunctionAnalysisManager fam;

        conv.run(*func,fam);
        func->dump();
    }
    }
}