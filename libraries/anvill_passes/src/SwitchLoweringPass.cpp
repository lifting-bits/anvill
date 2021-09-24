#include <anvill/Transforms.h>
#include "SwitchLoweringPass.h"
#include <anvill/ABI.h>
#include <llvm/Analysis/ConstantFolding.h>
#include <llvm/IR/PatternMatch.h>
#include <iostream>
#include <llvm/IR/Dominators.h>
#include <llvm/Pass.h>
#include <llvm/IR/DerivedUser.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/Analysis/CFG.h>
#include <llvm/IR/InstVisitor.h>
#include <optional>
#include <memory>
#include <numeric>
#include <unordered_set>

/*

Ok idea we fold in reverse up the definition of the pc in the intrinsic to attempt to get an expr of the form:
[Add(load(T+[index-normalizer]*w),pc)] This is the first expr we need and it defines the actual jump 
542:                                              ; preds = %529
  %543 = add i8 %22, -6
  %544 = icmp ult i8 %543, 29
  %545 = icmp eq i8 %22, 35
  %546 = or i1 %545, %544
  %547 = select i1 %546, i32 12, i32 -2054803
  %548 = add i32 %537, %547
  %549 = add i32 %548, 9
  br i1 %546, label %550, label %41

550:                                              ; preds = %542
  %551 = zext i8 %543 to i32
  %552 = shl nuw nsw i32 %551, 2
  %553 = add nuw nsw i32 %552, 136968824
  %554 = inttoptr i32 %553 to i32*
  %555 = load i32, i32* %554, align 4
  %556 = add i32 %555, 137732096
  %557 = call i32 (i32, ...) @__anvill_complete_switch(i32 %556, i32 134522973, i32 136578775, i32 136578784, i32 136578793, i32 136578809, i32 136578818)
  %558 = add i32 %555, 137732105
  switch i32 %557, label %559 [
    i32 0, label %41
    i32 1, label %560
    i32 2, label %563
    i32 3, label %566
    i32 4, label %569
    i32 5, label %573
  ]


where T

*/

namespace anvill {
    namespace {
        template <unsigned N> llvm::SmallSet<const llvm::BranchInst*, N> getTaintedBranches(const llvm::Value* byVal) {
            std::vector<const llvm::Value*> worklist;
            llvm::SmallSet<const llvm::Value*,20> closedList; 
            worklist.push_back(byVal);
            llvm::SmallSet<const llvm::BranchInst*,10> taintedGuards;

            while (!worklist.empty()) {
                const llvm::Value* curr = worklist.back();
                worklist.pop_back();
                closedList.insert(curr);
                if (const llvm::BranchInst * branch = llvm::dyn_cast<llvm::BranchInst>(curr)) {
                    taintedGuards.insert(branch);
                }

                for (const auto& useOfIndex : curr->uses()) {
                    if (closedList.find(useOfIndex) == closedList.end()) {
                        worklist.push_back(useOfIndex.get());
                    }
                }
            }

            return taintedGuards;
        }


        bool isTargetInstrinsic(const llvm::CallInst* callinsn) {
            if (const auto *callee = callinsn->getCalledFunction()) {
                return callee->getName().equals(kAnvillSwitchCompleteFunc);
            }

            return false;
        }

        std::vector<const llvm::CallInst*> getTargetCalls(const llvm:: Function &F) {
        std::vector<const llvm::CallInst*> calls;
        for (const auto& blk: F.getBasicBlockList()) {
            for(const auto& insn: blk.getInstList()) {
                const llvm::Instruction* new_insn = &insn;
                if (const llvm::CallInst* call_insn = llvm::dyn_cast<llvm::CallInst>(new_insn)) {
                    if(isTargetInstrinsic(call_insn)) {
                        calls.push_back(call_insn);
                    }
                }
            }
        }
        return calls;
    }

    }

 
    char SwitchLoweringPass::ID = '\0';

   
    struct JumpTableResult {
        
    };

    namespace pats = llvm::PatternMatch;


    struct BoundsCheck {
        const llvm::BranchInst* branch;
        bool passesCheckOnTrue;
    };

    enum Connective {AND, OR};
  
    class LinearConstraint {
        private:
            llvm::CmpInst::Predicate comp;
            
            llvm::APInt bound;

            static llvm::CmpInst::Predicate normalizeComp(llvm::CmpInst::Predicate orig) {
                if (llvm::CmpInst::isSigned(orig)) {
                    orig = llvm::CmpInst::getUnsignedPredicate(orig);
                }

                if (llvm::CmpInst::isNonStrictPredicate(orig)) {
                    orig = llvm::CmpInst::getStrictPredicate(orig);
                }

                return orig;
            }

        public:
            LinearConstraint(llvm::CmpInst::Predicate comp,llvm::APInt bound): comp(normalizeComp(comp)),bound(bound) {}


            void logicalNot() {
                this->comp = llvm::CmpInst::getInversePredicate(this->comp);
            }


            // compute exclusive upper bound if this comparison asserts that the index is less than some constant
            std::optional<llvm::APInt> computeUB() {
                // comp is normalized to the strict unsigned predicate so:
                assert(llvm::CmpInst::isStrictPredicate(this->comp) && llvm::CmpInst::isUnsigned(this->comp) && llvm::CmpInst::isIntPredicate(this->comp));
                switch(this->comp) {
                    case llvm::CmpInst::Predicate::ICMP_ULT :
                        return {this->bound}; 
                    default:
                        return {};
                };
            }

    };






    /*
    If this becomes an issue this could be come a tree of expressions, and actually apply solving
    */
    class ConstraintList {
        private: 
            std::vector<LinearConstraint> cons;
            std::optional<Connective> conn;

        void flipConnective() {
            if(this->conn) {
                if (*this->conn == Connective::AND) {
                    this->conn = {Connective::OR};
                } else {
                    this->conn = {Connective::AND};
                }
            }
        }

        std::optional<llvm::APInt> combiner(std::optional<llvm::APInt> total, LinearConstraint newCons) {
            auto newUpperBound = newCons.computeUB();

            if (this->conn == Connective::AND) {
                // essentially intersection (meet)
                if (total && !newUpperBound) {
                    return total;
                }

                if (newUpperBound && ! total) {
                    return newUpperBound;
                }

                return newUpperBound->ugt(*total) ? newUpperBound : total;
            } else {
                if (total && !newUpperBound) {
                    return newUpperBound;
                }

                if (newUpperBound && ! total) {
                    return total;
                }

                return newUpperBound->ugt(*total) ? total : newUpperBound;
            }
        }

        public:
            ConstraintList(LinearConstraint lcons): cons({lcons}), conn({}) {

            }


            std::optional<ConstraintList> addConstraint(ConstraintList other,Connective conn) {
                if (!this->conn) {
                    this->conn = conn;
                }

                if (other.conn && *other.conn != *this->conn) {
                    this->cons.insert(this->cons.end(),other.cons.begin(),other.cons.end());
                    return {*this};
                }

                return {};
            }


            void logicalNot() {
                this->flipConnective();
                std::for_each(this->cons.begin(), this->cons.end(), [](LinearConstraint& lcons) {lcons.logicalNot();});
            }

            // exclusive upper bound on the index
            std::optional<llvm::APInt> computeUB() {
                // basically a fold with max/min as the combinator depending on or/and connective and then each lcons just returns either unbounded or bound
                std::optional<llvm::APInt> start;
                return std::accumulate(this->cons.begin(), this->cons.end(),start, [](std::optional<llvm::APInt> total, LinearConstraint newCons){ return total;});
            }
    };

    // core assumption currently constraints are treated as unsigned
    class ConstraintExtractor: public llvm::InstVisitor<ConstraintExtractor,std::optional<ConstraintList>> {
        private:


            static std::optional<Connective> translateOpcodeToConnective(llvm::Instruction::BinaryOps op) {
                switch (op)
                {
                case llvm::Instruction::And /* constant-expression */:
                    /* code */
                    return {Connective::AND};
                case llvm::Instruction::Or:
                    return {Connective::OR};
                default:
                    return {};
                }
            }



            const llvm::Value* index;


        public: 

            std::optional<ConstraintList> expectInsn(llvm::Value* v) {
                if (auto* insn = llvm::dyn_cast<llvm::Instruction>(v)) {
                    return this->visit(*insn);
                }

                return {};
            }


            ConstraintExtractor(const llvm::Value* index): index(index) {}


            std::optional<ConstraintList> visitInstruction(llvm::Instruction &I ) {
                return {};
            }

            std::optional<ConstraintList> visitICmpInst(llvm::ICmpInst &I) {
                // because instruction combiner places constants on the right hand side we can assume:

                if (auto *rhsBound = llvm::dyn_cast<llvm::ConstantInt>(I.getOperand(1))) {
                    llvm::APInt apBound = rhsBound->getValue();

                    // compared directly to index
                    if (I.getOperand(0) == this->index) {
                        auto lcons = LinearConstraint(I.getPredicate(),apBound);
                        auto list = ConstraintList(lcons);
                        return {list};
                    }


                    llvm::Value* candidateIndex;
                    llvm::ConstantInt* added;
                    if (pats::match(I.getOperand(0),pats::m_Add(pats::m_Value(candidateIndex),pats::m_ConstantInt(added))) && candidateIndex == this->index) {
                        auto addedToIndex = added->getValue();
                        auto newBound = apBound - addedToIndex; // subtract accross bound to normalize bound to index
                        LinearConstraint lcons(I.getPredicate(),newBound);
                        auto list = ConstraintList(lcons);
                        return {list};
                    }

                }

                return {};
            }

            std::optional<ConstraintList>  visitBinaryOperator(llvm::BinaryOperator &B) {
                auto conn = translateOpcodeToConnective(B.getOpcode());



                if (auto repr0 = this->expectInsn(B.getOperand(0))) {
                    if (auto repr1 = this->expectInsn(B.getOperand(1))) {
                        if (conn) {
                            return repr0->addConstraint(*repr1, *conn);
                        }
                    }
                }

                return {};
            }


            
    };

    class JumpTableDiscovery {
        private:
            llvm::ConstantInt* jumpTableAddr;
            llvm::ConstantInt* programCounter;
            llvm::Value* index;
            llvm::ConstantInt* normalizer;
            const llvm::DominatorTree& DT;
            std::optional<llvm::APInt> upperBound;

        private:

            std::optional<BoundsCheck> translateTerminatorToBoundsCheck(  llvm::Instruction* term, const llvm::BasicBlock* targetCTIBlock ) {
                if (auto branch = llvm::dyn_cast<llvm::BranchInst>(term)) {
                    if (branch->getNumSuccessors() != 2) {
                        return {};
                    }

                    const llvm::Instruction* firstCTIInsns = targetCTIBlock->getFirstNonPHI();
                    const llvm::SmallPtrSet<llvm::BasicBlock * ,1> checkSet{branch->getParent()};
                    const llvm::SmallPtrSetImpl<llvm::BasicBlock *> *st = &checkSet; 

                    // newer versions of llvm let you go from blocks...
                    // TODO should pass loop info
                    bool canReachCTIWithoutCheckS0 = llvm::isPotentiallyReachable( branch->getSuccessor(0)->getFirstNonPHI(),firstCTIInsns,st,&this->DT);
                    bool canReachCTIWithoutCheckS1 = llvm::isPotentiallyReachable( branch->getSuccessor(1)->getFirstNonPHI(),firstCTIInsns,st, &this->DT);

                    if (canReachCTIWithoutCheckS0 && (! canReachCTIWithoutCheckS1)) {
                        return {{branch,true}};
                    }

                    if ((!canReachCTIWithoutCheckS0) && canReachCTIWithoutCheckS1) {
                        return {{branch,false}};
                    }
                }
                return {};
            }

            bool runBoundsCheckPattern(const llvm::CallInst* intrinsicCall) {
                assert(this->index != nullptr);
                auto taintedBranches = getTaintedBranches<10>(this->index);
                auto dtNode = this->DT.getNode(intrinsicCall->getParent());
                auto inode = dtNode->getIDom()->getBlock();
                auto term = inode->getTerminator();
                auto maybe_bcheck = this->translateTerminatorToBoundsCheck(term, intrinsicCall->getParent());
                if (maybe_bcheck) {
                    auto bcheck = *maybe_bcheck;
                    auto cond = bcheck.branch->getCondition();
                    auto indexConstraints = ConstraintExtractor(this->index).expectInsn(cond);

                    if(indexConstraints) {
                        auto cons = *indexConstraints;
                        if (!bcheck.passesCheckOnTrue) {
                            // we want the conditions s.t. the check passes
                            cons.logicalNot();
                        }

                        this->upperBound = cons.computeUB();
                        return this->upperBound.has_value();
                    }

                }

                return false;
            }

            bool runIndexPattern(const llvm::Value* pcArg) {
                // this pattern could be screwed up by ordering of computation should have multiple cases at different stages
                // TODO figure out commuting (InstructionCombiner should kinda take care of this anyways)

                // to ensure this transformation is valid we now need to find the bounds check and ensure it lines up with the table.


                llvm::Value* potentialIndexExpr = nullptr;
                auto pat = pats::m_Add(
                    pats::m_Load(
                        pats::m_IntToPtr(
                            pats::m_Add(
                            pats::m_BinOp(pats::m_Value(potentialIndexExpr),pats::m_ConstantInt()),
                                pats::m_ConstantInt(this->jumpTableAddr)))),
                pats::m_ConstantInt(this->programCounter));
                if (pats::match(pcArg,pat)) {
     
                    // TODO handle case where there is no index

                    // ok tricky bit here is the index can be of any size up to word size really, turns out not so tricky 
                    auto indexAdd = pats::m_Add(pats::m_Value(this->index), pats::m_ConstantInt(this->normalizer));
                    return pats::match(potentialIndexExpr,pats::m_ZExtOrSExtOrSelf(indexAdd));
                } else {
                    return false;
                }

                std::cout << "Index Pattern" << std::endl; 
            }
            
           

        public:
            JumpTableDiscovery(const llvm::DominatorTree& DT): jumpTableAddr(nullptr), programCounter(nullptr),index(nullptr), normalizer(nullptr), DT(DT)  {
            }




        // Definition a jump table bounds compare is a compare that uses the index and is used by a break that jumps to a block that may reach the indirect jump block or *must* not. the comparing block should dominate the indirect jump


        bool runPattern(const llvm::CallInst* pcCall) {
            return this->runIndexPattern(pcCall->getArgOperand(0)) && this->runBoundsCheckPattern(pcCall);

        }  
    };
   




    void SwitchLoweringPass::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
        AU.setPreservesCFG(); // is this true?
        AU.addRequired<llvm::DominatorTreeWrapperPass>();
    
    }

    bool SwitchLoweringPass::runOnFunction(llvm::Function &F) {
        auto targetCalls = getTargetCalls(F);
        const llvm::DominatorTree & DT = this->getAnalysis<llvm::DominatorTreeWrapperPass>().getDomTree();

        JumpTableDiscovery jumpDisc(DT);
        for(const auto& targetCall: targetCalls) {
            if (jumpDisc.runPattern(targetCall)) {
                std::cout << "Found switch to lower" << std::endl; 
            
            }
        }
        


        return false;
    }

    llvm::FunctionPass* CreateSwitchLoweringPass() {
        return new SwitchLoweringPass();
    }

    llvm::StringRef SwitchLoweringPass::getPassName() const {
        return "SwitchLoweringPass";
    }

}