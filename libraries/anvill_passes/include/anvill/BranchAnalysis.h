/*
 * Copyright (c) 2021 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

// This pass utilizes the ConstraintExtractor to attempt to prove that a computation over flags hinted by "__remill_flag_computation_*".
// The pass attempts to simplify comparisons which are hinted by the intrinsics: "__remill_compare_*". The general strategy is to generate
// the set of symbolic constraints that represent a given __remill_compare computation. The constraint generation visitore stops at each flag computation
// and emits a set of symbolic constraints that represent that flag. All flag computations should be the result of some arithmetic operation on
// two values. If the flags depend on more than two values, the branch analysis does not return a result for that branch.
// Once the symbolic constraints have been collected and the two compared values have been selected, then the analyzer attempts to prove that a guessed
// comparison between the two values is exactly equivalent to the flag constraints.
// This proof works by confirming that there is no counterexample where the guessed output is different to the flag computation output.
// If the proof is succesful the branch analysis stores the two values and the comparison between them that represents the flag computation.
// The analysis is extensible with additional strategies to emit guesses.
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