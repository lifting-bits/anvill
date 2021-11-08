#pragma once

#include <anvill/ABI.h>
#include <anvill/BranchHintPass.h>
#include <anvill/Constraints.h>
#include <anvill/IntrinsicPass.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/ValueMap.h>
#include <llvm/Pass.h>

namespace anvill {
// Proven equivalent comparison

typedef std::pair<llvm::Value *, llvm::Value *> ComparedValues;
struct BranchResult {
  ComparedValues compared;
  llvm::CmpInst::Predicate compare;
};


extern const std::string kFlagIntrinsicPrefix;
extern const std::string kCompareInstrinsicPrefix;

// newtype of Predicate
struct RemillComparison {
  llvm::CmpInst::Predicate pred;
};

enum ArithFlags { OF, ZF, SIGN, CARRY };
struct RemillFlag {
  ArithFlags flg;
  llvm::Value *over;
};


class Guess {
 private:
  llvm::CmpInst::Predicate op;
  Z3Binop z3_op;
  bool flip_symbols;

 public:
  Guess(llvm::CmpInst::Predicate op, bool flip_symbols);

  // Attempts to prove the guess, should leave the solver and context as they were so uses push pop
  bool AttemptToProve(z3::expr flagRes, z3::solver &solv, z3::context &cont,
                      const Environment &env);


  BranchResult ConstructSimplifiedCondition(ComparedValues symbs);
};

RemillComparison ParseComparisonIntrinsic(llvm::StringRef intrinsic_name);

// TODO(ian): perhaps this isnt a generally useful parse function, should maybe narrow it
std::optional<RemillFlag> ParseFlagIntrinsic(const llvm::Value *value);


class BranchAnalysis
    : public BranchHintPass<BranchAnalysis,
                            llvm::DenseMap<llvm::CallInst *, BranchResult>>,
      public llvm::AnalysisInfoMixin<BranchAnalysis> {
 private:
  friend llvm::AnalysisInfoMixin<BranchAnalysis>;
  static llvm::AnalysisKey Key;
  std::vector<std::function<Guess(llvm::CmpInst::Predicate)>>
      guess_generation_strategies;
  std::optional<BranchResult> analyzeComparison(llvm::CallInst *intrinsic_call);

 public:
  BranchAnalysis() {
    // TODO(ian): Should add cartesian product strategy combinator to eliminate the need to manually specify these.
    // Would require allowing strategies to return multiple guesses.
    this->guess_generation_strategies.push_back(
        [](llvm::CmpInst::Predicate hint) { return Guess(hint, false); });
    this->guess_generation_strategies.push_back(
        [](llvm::CmpInst::Predicate hint) {
          return Guess(llvm::CmpInst::getInversePredicate(hint), false);
        });
    this->guess_generation_strategies.push_back(
        [](llvm::CmpInst::Predicate hint) { return Guess(hint, true); });
    this->guess_generation_strategies.push_back(
        [](llvm::CmpInst::Predicate hint) {
          return Guess(llvm::CmpInst::getInversePredicate(hint), true);
        });
  }

  BranchAnalysis(std::vector<std::function<Guess(llvm::CmpInst::Predicate)>>
                     guess_generation_strategies)
      : guess_generation_strategies(std::move(guess_generation_strategies)) {}


  // Maps CallInst to anvill_compare prims to the result
  using Result = llvm::DenseMap<llvm::CallInst *, BranchResult>;

  static Result INIT_RES;


  Result runOnIntrinsic(llvm::CallInst *indirectJump,
                        llvm::FunctionAnalysisManager &am, Result agg);


  static llvm::StringRef name();
};
}  // namespace anvill