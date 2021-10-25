#include <anvill/ABI.h>
#include <anvill/JumpTableAnalysis.h>
#include <anvill/SliceManager.h>
#include <anvill/Transforms.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/CFG.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <z3++.h>

#include <numeric>
#include <optional>

#include "SlicerVisitor.h"

// The goal of this analysis pass is to recover the structure of jump tables for indirect control flow transfers under the following constraints:
// 1. The program counter only depends on one non-constant value which is a load.
// 2. The load address only depend on one non-constant value which is the index.
// 3. The immediate dominator of the block containing the indirect jump contains a conditional that either does or does not visit the indirect jump without returning to the check.
// 4. The check only depends on one non-constant value which is the index.
// 5. The only non-constant in the check is the index, which can derive bounds for.

// The pass returns a program counter slice, load address slice, index, and bounds on the index if the above conditions hold.

// Consider the jump table below (instructions filtered for only the relevant ones).

// 18:                                               ; preds = %2
//   %19 = call i64 @_atoi()
//   %20 = trunc i64 %19 to i32
//   %21 = add i32 %20, 4
//   %22 = zext i32 %21 to i64
//   %23 = icmp ugt i32 %21, 7
//   br i1 %23, label %33, label %25

// 25:                                               ; preds = %18
//   %26 = shl nuw nsw i64 %22, 2
//   %27 = add nuw nsw i64 %26, 4294983520
//   %28 = inttoptr i64 %27 to i32*
//   %29 = load i32, i32* %28, align 4
//   %30 = sext i32 %29 to i64
//   %31 = add nsw i64 %30, 4294983436
//   %32 = call i64 (i64, ...) @__anvill_complete_switch(i64 %31, i64 4294983452, i64 4294983464, i64 4294983476, i64 4294983484, i64 4294983496)
//   switch i64 %32, label %34 [
//     i64 0, label %35
//     i64 1, label %36
//     i64 2, label %37
//     i64 3, label %38
//     i64 4, label %33
//   ]

// The first step the pass takes is to slice the program counter in the target intrinsic. In this case %31. Slicing for both slices is performed in runIndexPattern.
// Slicing depends on the SliceVisitor. The slice visitor visits instructions and stops when the instruction becomes non constant. The slicer returns both a vector of linear instructions
// that were reached before the stop value and the value it stopped at.

// For %31, the slice visitor will return a slice [%30,%31] and a stop value of %29. After retrieving this slice and stop value the index pattern checks for condition 1. If condition 1 holds, then the returned
// stop value for slicing the pc should be a load instruction. In this case, %29 is a load so the check passes.
// Now the index pattern runs for condition 2. The address of the load (%28) is run through the slicer retrieving a slice and stop value. The stop value is the first constant within the load address computation, so the stop value becomes the index.
// The slice is the associated index slice. In this case the stop value for a slice on %28 is %19 with the slice [%20,%21,%22,%26,%27,%28].


// The algorithm now proceeds to the bounds check pattern which firsts checks step 3, then 4, and then 5. It checks if the immediate dominator of the block containing the indirect jump terminates in a branch (In this case it does).
// The branch is then examined to determine if one exit reaches the target jump while the other exit cannot reach the target jump without traversing the check again. The LLVM cfg function llvm::isPotentiallyReachable works well
// for checking these properties.
// The branch label that doesnt reach the jump is considered the default out label of the jump table. In this case the false case reaches the jump so the true case label: %33 is considered the defaultOut.
// passesCheckOnTrue is set to false since it passes the jump table check when the condition is false.
//
// The algorithm now checks 4 utilizing the Constraint extractor. The constraint extractor extracts constant constraints on the index by visiting the instructions in the def use chain for the check.
// For technical reasons, if a cast is reached in this slice and the cast is a member of the index slice (defines the index) then the index is updated to the cast. This update is done, because tight continous bounds do not exist on
// casted values. In the example above the constraint extractor starts from %23 and collects a ugt constraint between %21 and %7. The extractor then visits %21. %21 becomes an add between %20 and 4. The extractor then reaches %20 which is a cast.
// %20 is in the index slice ([%20,%21,%22,%26,%27,%28]) so the index is updated to %20 and the final index slice becomes ([%21,%22,%26,%27,%28]). The collected constraint on the index is of the form: (bvugt (bvadd index 4) 7).
// Finally, if passesCheckOnTrue is false the constraints are negated, because we want the constraints that reach the target jump. In this case the target jump is reached in the false portion of the branch so the constraints are negated resulting in:
// (not (bvugt (bvadd index 4) 7))

// The algorithm is now ready for step 5 which derives the bounds on the index. The process is described precisely in solveForBounds, but the general approach is to derive a minimum and maximum index value that satisfies the collected constraint.
// The minimum and maximum are then proven to be a conservative bound on the index by augmenting the constraint with additional constraints stating the index is outside of the recovered bounds. If z3 is able to prove the augmented constraints are unsat,
// then the bounds are safe. Two bounds are recovered: unsigned bounds on index and signed bounds on index. Since both bounds are conservative, either bound is valid, so we select the narrower bound.
// The unsigned bound on %20 in the above is: [0, 4294967295]. The signed bound is [-4, 3] so the signed bound is selected.

// Plausible bound recovery alternatives include lightweight VSA to determine some strided interval etc on the index, avoiding the need for z3.

// The final returned information is the index bounds, the defaultOut, the final index, the final index slice, and the program counter slice.
// defaultOut: %33
// index bounds: [-4,3]
// index: %20
// index slice: [%21,%22,%26,%27,%28]
// pc slice: [%30,%31]

namespace anvill {
namespace {
template <unsigned N>
static llvm::SmallSet<const llvm::BranchInst *, N>
GetTaintedBranches(const llvm::Value *byVal) {
  std::vector<const llvm::Value *> worklist;
  llvm::SmallSet<const llvm::Value *, 20> closed_list;
  worklist.push_back(byVal);
  llvm::SmallSet<const llvm::BranchInst *, 10> tainted_guards;

  while (!worklist.empty()) {
    const llvm::Value *curr = worklist.back();
    worklist.pop_back();
    closed_list.insert(curr);
    if (const llvm::BranchInst *branch =
            llvm::dyn_cast<llvm::BranchInst>(curr)) {
      tainted_guards.insert(branch);
    }

    for (auto &use_of_index : curr->uses()) {
      if (closed_list.find(use_of_index) == closed_list.end()) {
        worklist.push_back(use_of_index.get());
      }
    }
  }

  return tainted_guards;
}

static llvm::APInt RunSingleIntFunc(SliceInterpreter &interp, SliceID slice,
                                    llvm::APInt indexValue) {
  std::vector<llvm::GenericValue> args(1);
  llvm::GenericValue v;
  v.IntVal = indexValue;
  args[0] = v;
  auto res = interp.executeSlice(slice, args);
  return res.IntVal;
}

static bool IsValidRelType(llvm::FunctionType *ty) {
  return ty->params().size() == 1 && ty->params()[0]->isIntegerTy() &&
         ty->getReturnType()->isIntegerTy();
}
}  // namespace

llvm::Value *IndexRel::getIndex() {
  return this->index;
}


namespace pats = llvm::PatternMatch;

struct BoundsCheck {
  const llvm::BranchInst *branch;
  bool passes_check_on_true;
  llvm::BasicBlock *fail_direction;
};

class Expr {
 public:
  virtual ~Expr() = default;
  virtual z3::expr BuildExpression(z3::context &c,
                                   z3::expr indexExpr) const = 0;
};

class AtomIndexExpr final : public Expr {

 public:
  z3::expr BuildExpression(z3::context &c, z3::expr indexExpr) const override {
    return indexExpr;
  }

  static std::unique_ptr<Expr> Create() {
    return std::make_unique<AtomIndexExpr>();
  }
};

class AtomIntExpr final : public Expr {
 private:
  llvm::APInt atom_value;

 public:
  static std::unique_ptr<bool[]> GetBigEndianBits(llvm::APInt api) {
    llvm::APInt toget_bits_from = api;

    // TODO(ian): verify endianess
    auto res = std::make_unique<bool[]>(toget_bits_from.getBitWidth());
    for (unsigned int i = 0; i < api.getBitWidth(); i++) {
      res[i] = toget_bits_from[i];
    }

    return res;
  }

  AtomIntExpr(llvm::APInt atomValue) : atom_value(atomValue) {}

  z3::expr BuildExpression(z3::context &c, z3::expr indexExpr) const override {
    auto bv_width = this->atom_value.getBitWidth();
    auto bv_bits = AtomIntExpr::GetBigEndianBits(this->atom_value);
    return c.bv_val(bv_width, bv_bits.get());
  }

  static std::unique_ptr<Expr> Create(llvm::APInt value) {
    return std::make_unique<AtomIntExpr>(value);
  }
};

// might be able to combine complex formula with binop tbh
// this technically allows (x /\ y) + (a /\ b) should maybe prevent these from being constructed, currently relies on the visitor to check and not construct.
enum Z3Binop { ADD, ULE, ULT, UGT, UGE, AND, OR, EQ, SGT, SGE, SLE, SLT };
class BinopExpr final : public Expr {
 private:
  Z3Binop opcode;
  std::unique_ptr<Expr> lhs;
  std::unique_ptr<Expr> rhs;

 public:
  BinopExpr(Z3Binop opcode, std::unique_ptr<Expr> lhs,
            std::unique_ptr<Expr> rhs)
      : opcode(opcode),
        lhs(std::move(lhs)),
        rhs(std::move(rhs)) {}


  static std::unique_ptr<Expr> Create(Z3Binop opcode, std::unique_ptr<Expr> lhs,
                                      std::unique_ptr<Expr> rhs) {
    return std::make_unique<BinopExpr>(opcode, std::move(lhs), std::move(rhs));
  }

  z3::expr BuildExpression(z3::context &c, z3::expr indexExpr) const override {
    auto e1 = this->lhs->BuildExpression(c, indexExpr);
    auto e2 = this->rhs->BuildExpression(c, indexExpr);
    switch (this->opcode) {
      case ADD: return z3::operator+(e1, e2);
      case ULE: return z3::ule(e1, e2);
      case ULT: return z3::ult(e1, e2);
      case UGT: return z3::ugt(e1, e2);
      case UGE: return z3::uge(e1, e2);
      case SGT: return z3::sgt(e1, e2);
      case SGE: return z3::sge(e1, e2);
      case SLT: return z3::slt(e1, e2);
      case SLE: return z3::sle(e1, e2);
      case EQ: return z3::operator==(e1, e2);
      case AND: return z3::operator&&(e1, e2);
      case OR: return z3::operator||(e1, e2);
      default: throw std::invalid_argument("unknown opcode binop");
    }
  }
};

enum Z3Unop { LOGNOT };
class UnopExpr final : public Expr {
 private:
  Z3Unop opcode;
  std::unique_ptr<Expr> lhs;

 public:
  UnopExpr(Z3Unop opcode, std::unique_ptr<Expr> lhs)
      : opcode(opcode),
        lhs(std::move(lhs)) {}

  static std::unique_ptr<Expr> Create(Z3Unop opcode,
                                      std::unique_ptr<Expr> lhs) {
    return std::make_unique<UnopExpr>(opcode, std::move(lhs));
  }

  z3::expr BuildExpression(z3::context &c, z3::expr indexExpr) const override {
    auto e1 = this->lhs->BuildExpression(c, indexExpr);
    switch (this->opcode) {
      case Z3Unop::LOGNOT: return z3::operator!(e1);
      default: throw std::invalid_argument("unknown opcode unop");
    }
  }
};

// Attempts to prove a narrow conservative bound on the index, utilizing the provided constraints.
class ExprSolve {
 private:
  std::optional<llvm::APInt> GetBound(
      z3::context &c, z3::expr index_bv, z3::expr constraints,
      std::function<z3::optimize::handle(z3::optimize, z3::expr)> gethandle,
      bool isSigned) {
    z3::optimize s(c);
    z3::params p(c);
    p.set("priority", c.str_symbol("pareto"));
    s.set(p);
    s.add(constraints);

    z3::expr tooptimize = index_bv;
    auto numbits = index_bv.get_sort().bv_size();
    auto sign_shift = llvm::APInt(numbits, 1).shl(numbits - 1);
    auto shift_bits = AtomIntExpr::GetBigEndianBits(sign_shift);
    z3::expr sign_shifted =
        (index_bv + c.bv_val(sign_shift.getBitWidth(), shift_bits.get()));

    if (isSigned) {
      tooptimize = sign_shifted;
    }


    auto h = gethandle(s, tooptimize);

    if (z3::sat == s.check()) {
      z3::expr res = s.lower(h);
      auto resint = llvm::APInt(index_bv.get_sort().bv_size(), res.as_uint64());
      if (isSigned) {
        // shift back into the signed domain
        return resint - sign_shift;
      } else {
        return resint;
      }
    } else {
      return std::nullopt;
    }
  }
  std::optional<Bound> OptomizeExpr(const std::unique_ptr<Expr> &exp,
                                    llvm::Value *index, bool isSigned) {


    z3::context c;
    z3::expr index_bv =
        c.bv_const("index", index->getType()->getIntegerBitWidth());
    z3::expr constraints = exp->BuildExpression(c, index_bv);
    auto ub = this->GetBound(
        c, index_bv, constraints,
        [](z3::optimize o, z3::expr toopt) -> z3::optimize::handle {
          return o.maximize(toopt);
        },
        isSigned);
    auto lb = this->GetBound(
        c, index_bv, constraints,
        [](z3::optimize o, z3::expr toopt) -> z3::optimize::handle {
          return o.minimize(toopt);
        },
        isSigned);

    if (!ub.has_value() || !lb.has_value()) {
      return std::nullopt;
    }

    auto ubbits = AtomIntExpr::GetBigEndianBits(*ub);
    auto lbbits = AtomIntExpr::GetBigEndianBits(*lb);
    z3::expr ub_val = c.bv_val(ub->getBitWidth(), ubbits.get());
    z3::expr lb_val = c.bv_val(lb->getBitWidth(), lbbits.get());

    z3::solver s(c);
    s.add(constraints);
    if (isSigned) {
      s.add(z3::sgt(index_bv, ub_val) || z3::slt(index_bv, lb_val));
    } else {
      s.add(z3::ugt(index_bv, ub_val) || z3::ult(index_bv, lb_val));
    }

    if (s.check() == z3::unsat) {
      // proven the bound
      return {{*lb, *ub, isSigned}};
    }

    return std::nullopt;
  }

 public:
  // Solving for the bounds on the index proceeds as follows:
  // The collected expressions are translated into z3 expressions.
  // These expressions are then added to an optimizer once to compute the maximum bound on the index variable and the minimum bound on the index.
  // We then attempt to prove the bound [l,u] is conservative. We build a constraint that includes the original constraints + (index < l || index > u).
  // If z3 can prove that these constraints are unsat, then we have proven a conservative bound on the index.
  // This algorithm is performed once for the unsigned range of the index and once for the index shifted into the signed domain by adding 2^{n-1}.
  // The signed domain can represent continous ranges on the index that wrap 0 tightly while the unsigned domain can represent values that wrap around 2^{n-1}.
  // The more narrow bounds are selected. The Bound structure keeps track of wether the bounds should use signed or unsigned comparison.
  std::optional<Bound> SolveForBounds(const std::unique_ptr<Expr> &exp,
                                      llvm::Value *index) {
    auto unsigned_bounds = this->OptomizeExpr(exp, index, false);
    auto signed_bounds = this->OptomizeExpr(exp, index, true);


    if (!signed_bounds.has_value()) {
      return unsigned_bounds;
    }

    if (!unsigned_bounds.has_value()) {
      return signed_bounds;
    }

    auto ub = *unsigned_bounds;
    auto sb = *signed_bounds;

    auto ub_size = ub.upper - ub.lower;
    auto sb_size = sb.upper - sb.lower;

    // diff should always be positive
    if (ub_size.ule(sb_size)) {
      return unsigned_bounds;
    } else {
      return signed_bounds;
    }
  }
};

class ConstraintExtractor
    : public llvm::InstVisitor<ConstraintExtractor,
                               std::optional<std::unique_ptr<Expr>>> {
 private:
  static std::optional<Z3Binop>
  TranslateOpcodeToConnective(llvm::Instruction::BinaryOps op) {
    switch (op) {
      case llvm::Instruction::BinaryOps::And /* constant-expression */:
        /* code */
        return {Z3Binop::AND};
      case llvm::Instruction::BinaryOps::Or: return {Z3Binop::OR};
      case llvm::Instruction::BinaryOps::Add: return {Z3Binop::ADD};
      default: return std::nullopt;
    }
  }


  static std::optional<Z3Binop>
  TranslateIcmpOpToZ3(llvm::CmpInst::Predicate op) {
    switch (op) {
      case llvm::CmpInst::Predicate::ICMP_EQ: return Z3Binop::EQ;
      case llvm::CmpInst::Predicate::ICMP_UGE: return Z3Binop::UGE;
      case llvm::CmpInst::Predicate::ICMP_UGT: return Z3Binop::UGT;
      case llvm::CmpInst::Predicate::ICMP_ULE: return Z3Binop::ULE;
      case llvm::CmpInst::Predicate::ICMP_ULT: return Z3Binop::ULT;
      case llvm::CmpInst::Predicate::ICMP_SGE: return Z3Binop::SGE;
      case llvm::CmpInst::Predicate::ICMP_SGT: return Z3Binop::SGT;
      case llvm::CmpInst::Predicate::ICMP_SLE: return Z3Binop::SLE;
      case llvm::CmpInst::Predicate::ICMP_SLT: return Z3Binop::SLT;
      default: return std::nullopt;
    }
  }


  const llvm::Value *index;
  const llvm::SmallPtrSetImpl<llvm::Instruction *> &alternative_indeces;

  std::optional<std::unique_ptr<Expr>>
  DieOrSubstitute(llvm::Instruction *maybealt) {
    if (this->alternative_indeces.contains(maybealt) &&
        (!this->substituded_index.has_value() ||
         *this->substituded_index == maybealt)) {
      this->substituded_index = {maybealt};
      return {AtomIndexExpr::Create()};
    }

    return std::nullopt;
  }

 public:
  std::optional<llvm::Instruction *> substituded_index;
  std::optional<std::unique_ptr<Expr>> ExpectInsnOrIndex(llvm::Value *v) {
    if (v == this->index) {
      return AtomIndexExpr::Create();
    }

    if (auto *constint = llvm::dyn_cast<llvm::ConstantInt>(v)) {
      return AtomIntExpr::Create(constint->getValue());
    }

    if (auto *insn = llvm::dyn_cast<llvm::Instruction>(v)) {
      return this->visit(*insn);
    }


    return std::nullopt;
  }


  ConstraintExtractor(
      const llvm::Value *index,
      const llvm::SmallPtrSetImpl<llvm::Instruction *> &alternativeIndeces)
      : index(index),
        alternative_indeces(alternativeIndeces) {}


  std::optional<std::unique_ptr<Expr>> visitInstruction(llvm::Instruction &I) {
    return std::nullopt;
  }

  std::optional<std::unique_ptr<Expr>> visitCastInst(llvm::CastInst &I) {
    return this->DieOrSubstitute(&I);
  }

  std::optional<std::unique_ptr<Expr>> visitICmpInst(llvm::ICmpInst &I) {
    auto conn = TranslateIcmpOpToZ3(I.getPredicate());


    if (auto repr0 = this->ExpectInsnOrIndex(I.getOperand(0))) {
      if (auto repr1 = this->ExpectInsnOrIndex(I.getOperand(1))) {
        if (conn) {
          return {
              BinopExpr::Create(*conn, std::move(*repr0), std::move(*repr1))};
        }
      }
    }

    return std::nullopt;
  }

  std::optional<std::unique_ptr<Expr>>
  visitBinaryOperator(llvm::BinaryOperator &B) {
    auto conn = TranslateOpcodeToConnective(B.getOpcode());


    if (auto repr0 = this->ExpectInsnOrIndex(B.getOperand(0))) {
      if (auto repr1 = this->ExpectInsnOrIndex(B.getOperand(1))) {
        if (conn) {
          return {
              BinopExpr::Create(*conn, std::move(*repr0), std::move(*repr1))};
        }
      }
    }

    return std::nullopt;
  }
};


class JumpTableDiscovery {
 private:
  std::optional<llvm::SmallVector<llvm::Instruction *>> pc_rel_slice;
  std::optional<llvm::SmallVector<llvm::Instruction *>> index_rel_slice;
  std::optional<llvm::Value *> index;
  std::optional<llvm::Value *> loaded_expression;
  std::optional<Bound> bounds;
  std::optional<llvm::BasicBlock *> default_out;
  const llvm::DominatorTree &dt;
  SliceManager &slices;


 private:
  // Determines the bounds check on an index that is used to compute an indirect CTI. A bounds check must guarentee that there is an exit
  // that reaches the CTI and another exit that never reaches the CTI without returning to the check. A check is represented as the branch and which direction
  // reaches the CTI.
  std::optional<BoundsCheck>
  TranslateTerminatorToBoundsCheck(llvm::Instruction *term,
                                   const llvm::BasicBlock *targetCTIBlock) {
    if (auto branch = llvm::dyn_cast<llvm::BranchInst>(term)) {
      if (branch->getNumSuccessors() != 2) {
        return std::nullopt;
      }

      const llvm::Instruction *first_cti_insns =
          targetCTIBlock->getFirstNonPHI();
      const llvm::SmallPtrSet<llvm::BasicBlock *, 1> check_set{
          branch->getParent()};
      const llvm::SmallPtrSetImpl<llvm::BasicBlock *> *st = &check_set;

      // newer versions of llvm let you go from blocks...
      // TODO(ian): should pass loop info
      bool can_reach_cti_without_check_s0 = llvm::isPotentiallyReachable(
          branch->getSuccessor(0)->getFirstNonPHI(), first_cti_insns, st,
          &this->dt);
      bool can_reach_cti_without_check_s1 = llvm::isPotentiallyReachable(
          branch->getSuccessor(1)->getFirstNonPHI(), first_cti_insns, st,
          &this->dt);

      if (can_reach_cti_without_check_s0 && (!can_reach_cti_without_check_s1)) {
        return {{branch, true, branch->getSuccessor(1)}};
      }

      if ((!can_reach_cti_without_check_s0) && can_reach_cti_without_check_s1) {
        return {{branch, false, branch->getSuccessor(0)}};
      }
    }
    return std::nullopt;
  }

  void ReplaceIndexWith(llvm::Instruction *newIndex) {
    this->index = newIndex;

    auto target = std::find(this->index_rel_slice->begin(),
                            this->index_rel_slice->end(), newIndex);

    assert(target != this->index_rel_slice->end());
    llvm::SmallVector<llvm::Instruction *> new_insn(
        std::next(target), this->index_rel_slice->end());
    this->index_rel_slice = {new_insn};
  }

  // Runs after the index has been selected. Determines the bounds on the index that are enforced by
  // The dominating branch terminator. These bounds are expressed as the inclusive lower and upper bound
  // of the index as well as wether the bound utilizes a signed compare.
  // Returns true if a bound was found.
  bool RunBoundsCheckPattern(const llvm::CallInst *intrinsicCall) {
    assert(this->index);
    auto dt_node = this->dt.getNode(intrinsicCall->getParent());
    auto inode = dt_node->getIDom()->getBlock();
    auto term = inode->getTerminator();
    auto maybe_bcheck = this->TranslateTerminatorToBoundsCheck(
        term, intrinsicCall->getParent());
    if (maybe_bcheck) {
      auto bcheck = *maybe_bcheck;
      this->default_out = {bcheck.fail_direction};
      auto cond = bcheck.branch->getCondition();
      llvm::SmallPtrSet<llvm::Instruction *, 10> index_slice_values(
          this->index_rel_slice->begin(), this->index_rel_slice->end());


      ConstraintExtractor extractor(*this->index, index_slice_values);
      std::optional<std::unique_ptr<Expr>> index_constraints =
          extractor.ExpectInsnOrIndex(cond);

      if (index_constraints) {
        if (extractor.substituded_index.has_value()) {
          this->ReplaceIndexWith(*extractor.substituded_index);
        }
        std::unique_ptr<Expr> cons = std::move(*index_constraints);
        if (!bcheck.passes_check_on_true) {
          // we want the conditions s.t. the check passes
          cons = UnopExpr::Create(Z3Unop::LOGNOT, std::move(cons));
        }


        ExprSolve s;
        this->bounds = s.SolveForBounds(cons, *this->index);
        return this->bounds.has_value();
      }
    }

    return false;
  }


 public:
  JumpTableDiscovery(const llvm::DominatorTree &DT, SliceManager &slices)
      : pc_rel_slice(std::nullopt),
        index_rel_slice(std::nullopt),
        index(std::nullopt),
        bounds(std::nullopt),
        dt(DT),
        slices(slices) {}


  // Definition a jump table bounds compare is a compare that uses the index and is used by a break that jumps to a block that may reach the indirect jump block or *must* not. the comparing block should dominate the indirect jump


  bool RunIndexPattern(llvm::Value *pcarg) {
    Slicer pcrel_slicer;

    if (auto *pcinst = llvm::dyn_cast<llvm::Instruction>(pcarg)) {
      llvm::Value *stop_point = pcrel_slicer.visit(pcinst);
      this->pc_rel_slice = pcrel_slicer.getSlice();

      llvm::Value *integer_load_expr = nullptr;
      if (pats::match(stop_point, pats::m_Load(pats::m_IntToPtr(
                                      pats::m_Value(integer_load_expr))))) {
        Slicer index_rel_slicer;
        this->loaded_expression = integer_load_expr;
        this->index = index_rel_slicer.checkInstruction(integer_load_expr);
        this->index_rel_slice = index_rel_slicer.getSlice();
        return true;
      }
    }

    return false;
  }


  std::optional<JumpTableResult> RunPattern(const llvm::CallInst *pcCall) {
    auto computed_pc = pcCall->getArgOperand(0);

    if (this->RunIndexPattern(computed_pc) &&
        this->RunBoundsCheckPattern(pcCall)) {
      SliceID pc_rel_id =
          this->slices.addSlice(*this->pc_rel_slice, computed_pc);
      SliceID index_rel_id = this->slices.addSlice(*this->index_rel_slice,
                                                   *this->loaded_expression);

      auto pc_rel_repr = this->slices.getSlice(pc_rel_id).getRepr();
      auto index_rel_repr = this->slices.getSlice(index_rel_id).getRepr();
      if (!IsValidRelType(pc_rel_repr->getFunctionType()) ||
          !IsValidRelType(index_rel_repr->getFunctionType())) {
        return std::nullopt;
      }

      PcRel pc(pc_rel_id);
      IndexRel index_relation(index_rel_id, *this->index);
      return {{pc, index_relation, *this->bounds, *this->default_out}};
    }

    return std::nullopt;
  }
};


llvm::IntegerType *PcRel::getExpectedType(SliceManager &slm) {
  auto slc = slm.getSlice(this->slice);
  return llvm::cast<llvm::IntegerType>(
      slc.getRepr()->getFunctionType()->params()[0]);
}


llvm::APInt PcRel::apply(SliceInterpreter &interp, llvm::APInt indexValue) {
  return RunSingleIntFunc(interp, this->slice, indexValue);
}

llvm::APInt IndexRel::apply(SliceInterpreter &interp, llvm::APInt indexValue) {
  return RunSingleIntFunc(interp, this->slice, indexValue);
}

llvm::DenseMap<llvm::CallInst *, JumpTableResult>
JumpTableAnalysis::runOnIndirectJump(llvm::CallInst *indirectJump,
                                     llvm::FunctionAnalysisManager &am,
                                     Result agg) {
  auto const &dt =
      am.getResult<llvm::DominatorTreeAnalysis>(*indirectJump->getFunction());

  llvm::DenseMap<llvm::CallInst *, JumpTableResult> results;
  JumpTableDiscovery jtdisc(dt, this->slices);
  auto res = jtdisc.RunPattern(indirectJump);
  if (res.has_value()) {
    agg.insert({indirectJump, *res});
  }
  return agg;
}


llvm::StringRef JumpTableAnalysis::name() {
  return "JumpTableAnalysis";
}

llvm::DenseMap<llvm::CallInst *, JumpTableResult> JumpTableAnalysis::INIT_RES =
    llvm::DenseMap<llvm::CallInst *, JumpTableResult>();


llvm::AnalysisKey JumpTableAnalysis::Key;

}  // namespace anvill
