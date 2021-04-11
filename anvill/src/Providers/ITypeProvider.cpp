#include "NullTypeProvider.h"
#include "ProgramTypeProvider.h"

namespace anvill {

ITypeProvider::Ptr ITypeProvider::CreateFromProgram(llvm::LLVMContext &context,
                                                    const IProgram &program) {
  return ProgramTypeProvider::Create(program, context);
}

ITypeProvider::Ptr ITypeProvider::CreateNull(void) {
  return NullTypeProvider::Create();
}

}  // namespace anvill
