/*
 * Copyright (c) 2021-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <anvill/Arch.h>
#include <anvill/Passes/LowerSwitchIntrinsics.h>
#include <anvill/Passes/JumpTableAnalysis.h>
#include <anvill/Providers.h>
#include <anvill/Transforms.h>
#include <doctest.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/OS/OS.h>
#include <iostream>

#include "Utils.h"
namespace anvill {


class MockMemProv : public MemoryProvider {
 private:
  std::map<uint64_t, uint8_t> memmap;
  const llvm::DataLayout &dl;
  uint64_t curr_base;

 public:
  MockMemProv(const llvm::DataLayout &dl) : dl(dl), curr_base(0) {}

  std::tuple<uint8_t, ByteAvailability, BytePermission>
  Query(uint64_t address) const {
    if (this->memmap.find(address) != this->memmap.end()) {
      auto val = this->memmap.find(address)->second;
      return std::make_tuple(val, ByteAvailability::kAvailable,
                             BytePermission::kReadable);
    }
    std::cout << "missed address: " << address << std::endl;
    return std::make_tuple(0, ByteAvailability::kUnavailable,
                           BytePermission::kReadable);
  }


  void SetCurrJumpTableBase(uint64_t baseAddress) {
    this->curr_base = baseAddress;
  }

  void AddJumpTableOffset(uint32_t offset) {
    std::vector<uint8_t> data(sizeof(uint32_t));
    if (dl.isLittleEndian()) {
      llvm::support::endian::write32le(data.data(), offset);
    } else {
      llvm::support::endian::write32be(data.data(), offset);
    }

    for (uint64_t i = 0; i < data.size(); i++) {
      this->memmap.insert({this->curr_base + i, data[i]});
    }

    this->curr_base += data.size();
  }
};


namespace {

static llvm::Function *FindFunction(llvm::Module *module, std::string name) {
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

    auto mod = LoadTestData(context, "SwitchLoweringLarge.ll");
    auto target_function =
        FindFunction(mod.get(), "sub_8240110__A_Sbi_Sbii_B_0");
    CHECK(target_function != nullptr);
    llvm::FunctionPassManager fpm;
    llvm::FunctionAnalysisManager fam;
    llvm::ModuleAnalysisManager mam;
    llvm::LoopAnalysisManager lam;
    llvm::CGSCCAnalysisManager cgam;

    llvm::PassBuilder pb;

    pb.registerFunctionAnalyses(fam);
    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerLoopAnalyses(lam);

    pb.crossRegisterProxies(lam, fam, cgam, mam);

    auto arch = BuildArch(context, remill::ArchName::kArchAMD64,
                          remill::OSName::kOSLinux);
    auto ctrl_flow_provider =
        anvill::NullControlFlowProvider();
    TypeDictionary tyDict(context);
    
    NullTypeProvider ty_prov(tyDict);
    NullMemoryProvider null_mem_prov;
    anvill::LifterOptions lift_options(
        arch.get(), *mod,ty_prov,std::move(ctrl_flow_provider),null_mem_prov);
    EntityLifter lifter(lift_options);
    fam.registerPass([&] { return JumpTableAnalysis(lifter); });

    fpm.addPass(llvm::InstCombinePass());
    auto mem_prov = std::make_shared<MockMemProv>(mod->getDataLayout());


    // this jump table has 30 entries with these possible offsets
    // -3209123, -1153321, -1153312, -1153303, -1153287, -1153278
    // the offset for the default lable %41 is -3209123
    // Since there are 30 entries in the table this test assumes the 5 offsets are in order bookending a bunch of default cases


    mem_prov->SetCurrJumpTableBase(136968824);
    mem_prov->AddJumpTableOffset(-1153321);
    mem_prov->AddJumpTableOffset(-1153312);
    for (int i = 0; i < 25; i++) {
      mem_prov->AddJumpTableOffset(-3209123);
    }

    mem_prov->AddJumpTableOffset(-1153303);
    mem_prov->AddJumpTableOffset(-1153287);
    mem_prov->AddJumpTableOffset(-1153278);

    fpm.addPass(LowerSwitchIntrinsics(*mem_prov.get()));
    fpm.run(*target_function, fam);


    const auto &analysis_results =
        fam.getResult<JumpTableAnalysis>(*target_function);

    REQUIRE(analysis_results.size() ==
            3);  // check that we resolve all the switches

    std::optional<std::reference_wrapper<const JumpTableResult>> recovered_switch = std::nullopt;
    llvm::CallInst *instrinsic = nullptr;
    for (const auto& jumpres : analysis_results) {
      // unfortunately values are no longer identifiable by labels because the pass requires the instruction combiner which will now run again so identify switch by first non default pc value.
      llvm::Value *v = jumpres.first->getArgOperand(2);
      const JumpTableResult& res = jumpres.second;
      auto interp = res.interp.getInterp();
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
          recovered_switch = {res};
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
    llvm::SwitchInst *lowered_switch =
        llvm::cast<llvm::SwitchInst>(instrinsic->getParent()->getTerminator());

    CHECK(lowered_switch->getNumCases() == 5);
    CHECK(lowered_switch->getCondition() ==
          recovered_switch->get().indexRel.getIndex());

    llvm::SmallSet<uint64_t, 10> allowed_indices;
    allowed_indices.insert(6);
    allowed_indices.insert(7);
    allowed_indices.insert(33);
    allowed_indices.insert(34);
    allowed_indices.insert(35);

    for (auto c : lowered_switch->cases()) {
      CHECK(allowed_indices.contains(
          c.getCaseValue()->getValue().getLimitedValue()));
    }

    lam.clear();
    fam.clear();
    mam.clear();
    cgam.clear();
  }

  TEST_CASE("Try negative Index") {
    llvm::LLVMContext context;
    auto mod = LoadTestData(context, "SwitchLoweringNeg.ll");
    auto target_function = FindFunction(mod.get(), "_start");
    CHECK(target_function != nullptr);
    llvm::FunctionPassManager fpm;
    llvm::FunctionAnalysisManager fam;
    llvm::ModuleAnalysisManager mam;
    llvm::LoopAnalysisManager lam;
    llvm::CGSCCAnalysisManager cgam;

    llvm::PassBuilder pb;

    pb.registerFunctionAnalyses(fam);
    pb.registerModuleAnalyses(mam);
    pb.registerCGSCCAnalyses(cgam);
    pb.registerLoopAnalyses(lam);

    pb.crossRegisterProxies(lam, fam, cgam, mam);

    auto arch = BuildArch(context, remill::ArchName::kArchAMD64,
                          remill::OSName::kOSLinux);
    auto ctrl_flow_provider =
        anvill::NullControlFlowProvider();
    TypeDictionary tyDict(context);
    
    NullTypeProvider ty_prov(tyDict);
    NullMemoryProvider null_mem_prov;
    anvill::LifterOptions lift_options(
        arch.get(), *mod,ty_prov,std::move(ctrl_flow_provider),null_mem_prov);
    EntityLifter lifter(lift_options);

    fam.registerPass([&] { return JumpTableAnalysis(lifter); });


    auto mem_prov = std::make_shared<MockMemProv>(mod->getDataLayout());


    mem_prov->SetCurrJumpTableBase(4294983520);
    mem_prov->AddJumpTableOffset(0x10);
    mem_prov->AddJumpTableOffset(0x3c);
    mem_prov->AddJumpTableOffset(0x3c);
    mem_prov->AddJumpTableOffset(0x1c);
    mem_prov->AddJumpTableOffset(0x28);
    mem_prov->AddJumpTableOffset(0x3c);
    mem_prov->AddJumpTableOffset(0x3c);
    mem_prov->AddJumpTableOffset(0x30);

    fpm.addPass(llvm::InstCombinePass());
    fpm.addPass(LowerSwitchIntrinsics(*mem_prov));

    fpm.run(*target_function, fam);


    const auto &analysis_results =
        fam.getResult<JumpTableAnalysis>(*target_function);

    REQUIRE(analysis_results.size() ==
            1);  // check that we resolve all the switches

    std::optional<std::reference_wrapper<const JumpTableResult>> recovered_switch = std::nullopt;
    llvm::CallInst *instrinsic = nullptr;
    for (const auto& jumpres : analysis_results) {
      auto interp = jumpres.second.interp.getInterp();
      // unfortunately values are no longer identifiable by labels because the pass requires the instruction combiner which will now run again so identify switch by first non default pc value.
      llvm::Value *v = jumpres.first->getArgOperand(2);
      const JumpTableResult& res = jumpres.second;
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
          recovered_switch = {res};
          break;
        default: CHECK(false);
      }
    }

    REQUIRE(instrinsic != nullptr);
    llvm::SwitchInst *lowered_switch =
        llvm::cast<llvm::SwitchInst>(instrinsic->getParent()->getTerminator());

    CHECK(lowered_switch->getNumCases() == 4);
    CHECK(lowered_switch->getCondition() ==
          recovered_switch->get().indexRel.getIndex());

    llvm::SmallSet<uint64_t, 10> allowed_indices;
    allowed_indices.insert(llvm::APInt(32, -4).getLimitedValue());
    allowed_indices.insert(llvm::APInt(32, -1).getLimitedValue());
    allowed_indices.insert(llvm::APInt(32, -0).getLimitedValue());
    allowed_indices.insert(llvm::APInt(32, 3).getLimitedValue());

    for (auto c : lowered_switch->cases()) {
      CHECK(allowed_indices.contains(
          c.getCaseValue()->getValue().getLimitedValue()));
    }

    fam.clear();
    cgam.clear();
    lam.clear();
    mam.clear();
  }
}

}  // namespace anvill
