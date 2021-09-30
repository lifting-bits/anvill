#include <doctest.h>
#include <iostream>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Verifier.h>
#include "Utils.h"
#include <anvill/Transforms.h>
#include <llvm/IR/Dominators.h>
#include <anvill/Providers/MemoryProvider.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>

namespace anvill {

    class MockMemProv: public MemoryProvider {
        private:
            std::map<uint64_t,uint8_t> memmap;
            const llvm::DataLayout&  dl;
            uint64_t currBase;

        public:

        MockMemProv(const llvm::DataLayout& dl): dl(dl), currBase(0) {

        }

        std::tuple<uint8_t, ByteAvailability, BytePermission>
            Query(uint64_t address) {
                if (this->memmap.find(address) != this->memmap.end()) {
                    auto val =  this->memmap[address];
                    return std::make_tuple(val,ByteAvailability::kAvailable,BytePermission::kReadable);
                }
                std::cout << "missed address: " << address << std::endl; 
                return std::make_tuple(0,ByteAvailability::kUnavailable,BytePermission::kReadable);
            }


        void setCurrJumpTableBase(uint64_t baseAddress) {
            this->currBase = baseAddress;
        }

        void addJumpTableOffset(uint32_t offset) {
            std::vector<uint8_t> data(sizeof(uint32_t));
            if (dl.isLittleEndian()) {
                llvm::support::endian::write32le(data.data(), offset);
            } else {
                llvm::support::endian::write32be(data.data(), offset);
            }

            for (uint64_t i = 0; i < data.size(); i++) {
                this->memmap.insert({this->currBase+i,data[i]});
            }

            this->currBase += data.size();
        }

    };


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
        fpm.add(llvm::createInstructionCombiningPass());
        fpm.add(CreateJumpTableAnalysis());
        auto memProv = std::make_shared<MockMemProv>(mod->getDataLayout());
        
        
        // this jump table has 30 entries with these possible offsets
        // -3209123, -1153321, -1153312, -1153303, -1153287, -1153278
        // the offset for the default lable %41 is -3209123
        // Since there are 30 entries in the table this test assumes the 5 offsets are in order bookending a bunch of default cases


        memProv->setCurrJumpTableBase(136968824);
        memProv->addJumpTableOffset(-1153321);
        memProv->addJumpTableOffset(-1153312);
        for (int i = 0; i < 25; i++) {
            memProv->addJumpTableOffset(-3209123);
        }

        memProv->addJumpTableOffset(-1153303);
        memProv->addJumpTableOffset(-1153287);
        memProv->addJumpTableOffset(-1153278);

        fpm.add(CreateSwitchLoweringPass(memProv));
        fpm.doInitialization();
        fpm.run(*targetFunction);
        fpm.doFinalization();

        targetFunction->dump();
    }
    }

}