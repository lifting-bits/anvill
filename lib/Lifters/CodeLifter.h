#include <anvill/Type.h>
#include <remill/BC/InstructionLifter.h>
#include <remill/BC/IntrinsicTable.h>

#include "anvill/Lifters.h"

namespace anvill {
/**
 * @brief A class that lifts machine level semantics to llvm
 * 
 */
class CodeLifter {
 protected:
  const LifterOptions &options;

  // Remill intrinsics inside of `module`.
  remill::IntrinsicTable intrinsics;

  remill::OperandLifter::OpLifterPtr op_lifter;

  // Are we lifting SPARC code? This affects whether or not we need to do
  // double checking on function return addresses;
  const bool is_sparc;

  // Are we lifting x86(-64) code?
  const bool is_x86_or_amd64;


  const MemoryProvider &memory_provider;
  const TypeProvider &type_provider;
  const TypeTranslator type_specifier;


  void RecursivelyInlineFunctionCallees(llvm::Function *inf);


  unsigned pc_annotation_id;

 public:
  CodeLifter(const LifterOptions &options);
};

}  // namespace anvill