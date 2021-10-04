#pragma once 

#include <memory>
#include <llvm/IR/Module.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/LLVMContext.h>
#include <tuple>
#include "SliceInterpreter.h"

namespace anvill {

    struct ClonedInstructions {
        llvm::ValueMap<llvm::Value*, llvm::Value*> mappingOldToNew;
        llvm::SmallVector<llvm::Instruction*> copied;
    };
    
    class SliceManager;
    class SliceID {
        friend class SliceManager;
        private:
            uint64_t ID;

            SliceID(): ID(0) {}

            SliceID operator++(int) {
                auto temp = *this;
                this->ID++;
                return temp;
            }
    };
    class SliceInterpreter;
    class SliceManager {
        
        public:
        class Slice {
            private:   
                llvm::Function* reprFunction;
                SliceID ID;
            // we need origin info for arguments somehow to basically allow analyses to get more context for the slice if they fail.
            public:
                Slice(llvm::Function* f, SliceID id): reprFunction(f), ID(id) {}

                llvm::Function* getRepr() {
                    return this->reprFunction;
                }
        };


        protected:
            llvm::LLVMContext context; // unique context?
            std::unique_ptr<llvm::Module> mod;

        private:
            // perhaps at some point we should split modules

            SliceID nextID;
            std::map<uint64_t, Slice> slices;
           
            llvm::SmallVector<llvm::Instruction*> createMapperFromSlice(llvm::ArrayRef<llvm::Instruction*> slice, llvm::ValueToValueMapTy& mapper);

            void insertClonedSliceIntoFunction(llvm::Function* targetFunc, llvm::Value* newRet, llvm::ArrayRef<llvm::Instruction*> slice);

            std::string getNextFunctionName(); 
            llvm::Function* createFunctionForCurrentID(llvm::ArrayRef<llvm::Value*> arguments, llvm::Value* returnVal);




        public:
            static std::string getFunctionName(SliceID id) {
                    return "sliceFunc." + std::to_string(id.ID);
            }

            /**
             * @brief Adds a slice of instructions to the slice manager. Any values not defined in the slice are lifted to arguments.
             * 
             * @param slice The instructions in the slice
             * @param returnValue The value 
             * @return SliceID The id for retrieving the slice. If the return value is not defined in the slice the return value will be lifted to an argument.
             */
            SliceID addSlice(llvm::ArrayRef<llvm::Instruction*> slice, llvm::Value* returnValue);


            Slice getSlice(SliceID id);

            SliceManager(): context(), mod(std::make_unique<llvm::Module>("slicemodule", this->context)), nextID(SliceID()) {
            }

            ~SliceManager() {
                this->mod.reset();
            }

            SliceInterpreter getInterp();

            
    };
}