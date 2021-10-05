#include <anvill/JumpTableAnalysis.h>
#include <anvill/Providers/MemoryProvider.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>

#include <iostream>

#include "Utils.h"
namespace anvill {

class MockMemProv : public MemoryProvider {
 private:
  std::map<uint64_t, uint8_t> memmap;
  const llvm::DataLayout &dl;
  uint64_t currBase;

 public:
  MockMemProv(const llvm::DataLayout &dl) : dl(dl), currBase(0) {}

  std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) {
    if (this->memmap.find(address) != this->memmap.end()) {
      auto val = this->memmap[address];
      return std::make_tuple(val, ByteAvailability::kAvailable,
                             BytePermission::kReadable);
    }
    std::cout << "missed address: " << address << std::endl;
    return std::make_tuple(0, ByteAvailability::kUnavailable,
                           BytePermission::kReadable);
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
      this->memmap.insert({this->currBase + i, data[i]});
    }

    this->currBase += data.size();
  }
};


namespace {

llvm::Function *findFunction(llvm::Module *module, std::string name) {
  for (auto &function : *module) {
    if (function.getName().equals(name)) {
      return &function;
    }
  }
  return nullptr;
}
}  // namespace

TEST_SUITE("SwitchLowerLargeFunction") {
  TEST_CASE("Run on large function") {
    llvm::LLVMContext context;
    SliceManager slc;
    JumpTableAnalysis *jta = new JumpTableAnalysis(slc);
    auto mod = LoadTestData(context, "SwitchLoweringLarge.ll");
    auto targetFunction =
        findFunction(mod.get(), "sub_8240110__A_Sbi_Sbii_B_0");
    CHECK(targetFunction != nullptr);
    llvm::legacy::FunctionPassManager fpm(mod.get());
    fpm.add(llvm::createInstructionCombiningPass());
    fpm.add(new llvm::DominatorTreeWrapperPass());
    fpm.add(jta);
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

    fpm.add(CreateSwitchLoweringPass(memProv, slc));
    fpm.doInitialization();
    fpm.run(*targetFunction);
    fpm.doFinalization();


    const auto &analysis_results = jta->getAllResults();

    REQUIRE(analysis_results.size() ==
            3);  // check that we resolve all the switches

    auto interp = slc.getInterp();
    std::optional<JumpTableResult> recoveredSwitch = std::nullopt;
    llvm::CallInst *instrinsic = nullptr;
    for (auto jumpres : analysis_results) {
      // unfortunately values are no longer identifiable by labels because the pass requires the instruction combiner which will now run again so identify switch by first non default pc value.
      llvm::Value *v = jumpres.first->getArgOperand(2);
      JumpTableResult res = jumpres.second;
      REQUIRE(llvm::isa<llvm::ConstantInt>(v));
      auto pc1 = llvm::cast<llvm::ConstantInt>(v);
      switch (pc1->getValue().getLimitedValue()) {
        case 136577416:
          CHECK(res.bounds.lower.getLimitedValue() == 3);
          CHECK(res.bounds.upper.getLimitedValue() == 241);
          CHECK(!res.bounds.isSigned);
          CHECK(res.indexRel.apply(interp, llvm::APInt(8, 5)) == 136967792);
          break;
        case 136578775:
          CHECK(res.bounds.lower.getLimitedValue() == 6);
          CHECK(res.bounds.upper.getLimitedValue() == 35);
          CHECK(!res.bounds.isSigned);
          CHECK(res.indexRel.apply(interp, llvm::APInt(8, 35)) == 136968940);
          instrinsic = jumpres.first;
          recoveredSwitch = {res};
          break;
        case 136578559:
          CHECK(res.bounds.lower.getLimitedValue() == 26);
          CHECK(res.bounds.upper.getLimitedValue() == 46);
          CHECK(!res.bounds.isSigned);
          CHECK(res.indexRel.apply(interp, llvm::APInt(8, 32)) == 136968764);
          break;
        default: CHECK(false);
      }
    }

    REQUIRE(instrinsic != nullptr);
    llvm::SwitchInst *loweredSwitch =
        llvm::cast<llvm::SwitchInst>(instrinsic->getParent()->getTerminator());

    CHECK(loweredSwitch->getNumCases() == 5);
    CHECK(loweredSwitch->getCondition() == recoveredSwitch->indexRel.index);

    llvm::SmallSet<uint64_t, 10> allowedIndices;
    allowedIndices.insert(6);
    allowedIndices.insert(7);
    allowedIndices.insert(8);
    allowedIndices.insert(34);
    allowedIndices.insert(35);

    for (auto c : loweredSwitch->cases()) {
      CHECK(allowedIndices.contains(
          c.getCaseValue()->getValue().getLimitedValue()));
    }
  }

  TEST_CASE("Try negative Index") {
    llvm::LLVMContext context;
    SliceManager slc;
    JumpTableAnalysis *jta = new JumpTableAnalysis(slc);
    auto mod = LoadTestData(context, "SwitchLoweringNeg.ll");
    auto targetFunction = findFunction(mod.get(), "_start");
    CHECK(targetFunction != nullptr);
    llvm::legacy::FunctionPassManager fpm(mod.get());
    fpm.add(llvm::createInstructionCombiningPass());
    fpm.add(new llvm::DominatorTreeWrapperPass());
    fpm.add(jta);
    auto memProv = std::make_shared<MockMemProv>(mod->getDataLayout());


    memProv->setCurrJumpTableBase(4294983520);
    memProv->addJumpTableOffset(0x10);
    memProv->addJumpTableOffset(0x3c);
    memProv->addJumpTableOffset(0x3c);
    memProv->addJumpTableOffset(0x1c);
    memProv->addJumpTableOffset(0x28);
    memProv->addJumpTableOffset(0x3c);
    memProv->addJumpTableOffset(0x3c);
    memProv->addJumpTableOffset(0x30);

    fpm.add(CreateSwitchLoweringPass(memProv, slc));
    fpm.doInitialization();
    fpm.run(*targetFunction);
    fpm.doFinalization();


    const auto &analysis_results = jta->getAllResults();

    REQUIRE(analysis_results.size() ==
            1);  // check that we resolve all the switches

    auto interp = slc.getInterp();
    std::optional<JumpTableResult> recoveredSwitch = std::nullopt;
    llvm::CallInst *instrinsic = nullptr;
    for (auto jumpres : analysis_results) {
      // unfortunately values are no longer identifiable by labels because the pass requires the instruction combiner which will now run again so identify switch by first non default pc value.
      llvm::Value *v = jumpres.first->getArgOperand(2);
      JumpTableResult res = jumpres.second;
      REQUIRE(llvm::isa<llvm::ConstantInt>(v));
      auto pc1 = llvm::cast<llvm::ConstantInt>(v);
      switch (pc1->getValue().getLimitedValue()) {
        case 4294983464:
          CHECK(res.bounds.lower == llvm::APInt(32, -4, true));
          CHECK(res.bounds.upper == llvm::APInt(32, 3, true));
          CHECK(res.bounds.isSigned);
          CHECK(res.indexRel.apply(interp, llvm::APInt(32, -3, true))
                    .getLimitedValue() == 4294983524);
          instrinsic = jumpres.first;
          recoveredSwitch = {res};
          break;
        default: CHECK(false);
      }
    }

    REQUIRE(instrinsic != nullptr);
    llvm::SwitchInst *loweredSwitch =
        llvm::cast<llvm::SwitchInst>(instrinsic->getParent()->getTerminator());

    CHECK(loweredSwitch->getNumCases() == 4);

    llvm::SmallSet<uint64_t, 10> allowedIndices;
    allowedIndices.insert(llvm::APInt(32, -4).getLimitedValue());
    allowedIndices.insert(llvm::APInt(32, -1).getLimitedValue());
    allowedIndices.insert(llvm::APInt(32, -0).getLimitedValue());
    allowedIndices.insert(llvm::APInt(32, 3).getLimitedValue());

    for (auto c : loweredSwitch->cases()) {
      CHECK(allowedIndices.contains(
          c.getCaseValue()->getValue().getLimitedValue()));
    }
  }
}

}  // namespace anvill