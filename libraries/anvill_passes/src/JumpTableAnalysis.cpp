#include "JumpTableAnalysis.h"
#include <llvm/ADT/SmallVector.h>
#include <anvill/Transforms.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/InstVisitor.h>
#include <anvill/ABI.h>
#include <numeric>
#include <optional>
#include <llvm/IR/Dominators.h>
#include <llvm/Analysis/CFG.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include "SlicerVisitor.h"
#include <anvill/SliceManager.h>

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

                for (auto& useOfIndex : curr->uses()) {
                    if (closedList.find(useOfIndex) == closedList.end()) {
                        worklist.push_back(useOfIndex.get());
                    }
                }
            }

            return taintedGuards;
        }


        LinearConstraint generateNoWrapPred(llvm::APInt constant) {
            if (constant.isNegative()) {
                return LinearConstraint(llvm::ICmpInst::Predicate::ICMP_UGE, constant);
            } else {
                return LinearConstraint(llvm::ICmpInst::Predicate::ICMP_ULE, llvm::APInt::getMaxValue(constant.getBitWidth()) - constant);
            }
        }
    }

    namespace pats = llvm::PatternMatch;

    struct BoundsCheck {
        const llvm::BranchInst* branch;
        bool passesCheckOnTrue;
        llvm::BasicBlock* failDirection;
    };

    enum Connective {AND, OR};
    enum LimitBoundType{BOTTOM,ULT,EQ, TOP};

    struct Bound  {
        LimitBoundType ty;
        llvm::APInt val;


        static Bound createTop() {
            return {LimitBoundType::TOP, llvm::APInt()};
        }

        static Bound createBottom() {
            return {LimitBoundType::BOTTOM, llvm::APInt()};
        }

        bool isBottom() {
            return this->ty == LimitBoundType::BOTTOM;
        }

        bool isTop() {
            return this->ty == LimitBoundType::TOP;
        }

        std::optional<llvm::APInt> getExclusiveMax() {
            switch(this->ty) {
                case LimitBoundType::TOP:
                case LimitBoundType::BOTTOM:
                    return std::nullopt;
                case LimitBoundType::ULT:
                    return {this->val};
                case LimitBoundType::EQ:
                    return {this->val + 1};
            }
        }

        Bound meet(Bound other) {
            if (this->isTop()) {
                return other;
            }

            if (other.isTop()) {
                return *this;
            }

            if (this->isBottom()) {
                return *this;
            }

            if (other.isBottom()) {
                return other;
            }

            if (this->ty == LimitBoundType::EQ && other.ty != LimitBoundType::EQ) {
                return other.meet(*this);
            }

            // both eq
            if (this->ty == LimitBoundType::EQ) {
                if (this->val == other.val) {
                    return {*this};
                } else {
                    return Bound::createBottom();
                }
            }

            // ult and other is eq
            if (other.ty == LimitBoundType::EQ) {
                if(other.val.ult(this->val)) {
                    return other;
                }
            }

            // ult and ult
            if (other.val.ult(this->val)) {
                return other;
            } else {
                return *this;
            }
        }

        static llvm::APInt apmin(llvm::APInt x, llvm::APInt y) {    
            if (x.ult(y)) {
                return x;
            } else {
                return y;
            }
        }


        static llvm::APInt apmax(llvm::APInt x, llvm::APInt y) {
            if (x.ugt(y)) {
                return x;
            } else {
                return y;
            }
        }

        Bound join(Bound other) {
            if (this->isTop()) {
                return *this;
            }

            if (other.isTop()) {
                return other;
            }

            if (this->isBottom()) {
                return other;
            }

            if (other.isBottom()) {
                return *this;
            }

            if (this->ty == LimitBoundType::EQ && other.ty != LimitBoundType::EQ) {
                return other.join(*this);
            }

            // both eq
            if (this->ty == LimitBoundType::EQ) {
                if (this->val == other.val) {
                    return {*this};
                } else {
                    return {LimitBoundType::ULT, Bound::apmax(this->val,other.val)+1};
                }
            }

            // ult and other is eq
            if (other.ty == LimitBoundType::EQ) {
                if(other.val.ult(this->val)) {
                    return *this;
                } else {
                    return {LimitBoundType::ULT, other.val+1};
                }
            }

            // ult and ult
            if (other.val.ult(this->val)) {
                return *this;
            } else {
                return other;
            }
        }

    };

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
            LinearConstraint(llvm::CmpInst::Predicate comp,llvm::APInt bound): comp(normalizeComp(comp)),bound(bound) {
                
            }


            void logicalNot() {
                this->comp = llvm::CmpInst::getInversePredicate(this->comp);
            }


            // compute exclusive upper bound if this comparison asserts that the index is less than some constant
            Bound computeUB() {
              
                // comp is normalized to the strict unsigned predicate so:
                // TODO dont do anything with equality would probably need SMT to help with figuring out bounds in that case
                assert(!llvm::CmpInst::isRelational(this->comp) || (llvm::CmpInst::isStrictPredicate(this->comp) && llvm::CmpInst::isUnsigned(this->comp) && llvm::CmpInst::isIntPredicate(this->comp)));
                switch(this->comp) {
                    case llvm::CmpInst::Predicate::ICMP_ULT :
                        return {LimitBoundType::ULT, this->bound}; 

                    case llvm::CmpInst::Predicate::ICMP_EQ:
                        return {LimitBoundType::EQ, this->bound};
                    default:
                        // assume all other cases to be unbounded
                        return Bound::createTop();
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
                if (this->conn == Connective::AND) {
                    this->conn = {Connective::OR};
                } else {
                    this->conn = {Connective::AND};
                }
            }
        }

        Bound getStartingBound() {
            if (*this->conn == Connective::AND) {
                return Bound::createTop();
            } else {
                return Bound::createBottom();
            }
        }



        Bound combiner(Bound total, Bound other) {
            switch(*this->conn) {
                case Connective::AND:
                    break;
                case Connective::OR:
                    break;
            }
            if ((*this->conn) == Connective::AND) {
                return total.meet(other);
            } else {
                return total.join(other);
            }
        } 

        public:
            ConstraintList(LinearConstraint lcons): cons({lcons}), conn(std::nullopt) {

            }


            std::optional<ConstraintList> addConstraint(ConstraintList other,Connective conn) {
                switch(conn) {
                    case Connective::AND:
                        break;
                    case Connective::OR:
                        break;
                }
                if (!this->conn) {
                    this->conn = {conn};
                }

                if (!other.conn || *other.conn == *this->conn) {
                    this->cons.insert(this->cons.end(),other.cons.begin(),other.cons.end());
                    return {*this};
                }

                return std::nullopt;
            }


            void logicalNot() {
                this->flipConnective();
                std::for_each(this->cons.begin(), this->cons.end(), [](LinearConstraint& lcons) {lcons.logicalNot();});
            }

            // exclusive upper bound on the index, must be sound (ie. guarenteed at runtime to be less than this value on the true path)
            Bound computeUB() {
                // basically a fold with max/min as the combinator depending on or/and connective and then each lcons just returns either unbounded or bound
                Bound start = this->getStartingBound();
                return std::accumulate(this->cons.begin(), this->cons.end(),start, [this](Bound total, LinearConstraint newCons){ return this->combiner(total,newCons.computeUB());});
            }
            
            // inclusive lower bound
            Bound computeLB() {
                Bound start = this->getStartBound();
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
                    return std::nullopt;
                }
            }



            const llvm::Value* index;


        public: 

            std::optional<ConstraintList> expectInsn(llvm::Value* v) {
                if (auto* insn = llvm::dyn_cast<llvm::Instruction>(v)) {
                    return this->visit(*insn);
                }

                return std::nullopt;
            }


            ConstraintExtractor(const llvm::Value* index): index(index) {}


            std::optional<ConstraintList> visitInstruction(llvm::Instruction &I ) {
                return std::nullopt;
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
                       
                        // ok this linear constraint isnt complete because doesnt account for wrapping
                        // this isnt strictly correct but assert that computation doesnt wrap, otherwise we would have to potentially express disjoint regions, SMT would solve this.
                        LinearConstraint lcons(I.getPredicate(),newBound);
                        auto list = ConstraintList(lcons);
                        list.addConstraint(generateNoWrapPred(addedToIndex), Connective::AND);
                        return {list};
                    }

                }
                return std::nullopt;
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

                return std::nullopt;
            }


            
    };



     class JumpTableDiscovery {
        private:
            
            
            
            std::optional<llvm::SmallVector<llvm::Instruction*>>  pcRelSlice;
            std::optional<llvm::SmallVector<llvm::Instruction*>>  indexRelSlice;
            std::optional<llvm::Value*> index;
            std::optional<llvm::Value*> loadedExpression;
            std::optional<llvm::APInt> upperBound;
            std::optional<llvm::BasicBlock*> defaultOut;
            const llvm::DominatorTree& DT;
            SliceManager& slices;
           

        private:

            std::optional<BoundsCheck> translateTerminatorToBoundsCheck(  llvm::Instruction* term, const llvm::BasicBlock* targetCTIBlock ) {
                if (auto branch = llvm::dyn_cast<llvm::BranchInst>(term)) {
                    if (branch->getNumSuccessors() != 2) {
                        return std::nullopt;
                    }

                    const llvm::Instruction* firstCTIInsns = targetCTIBlock->getFirstNonPHI();
                    const llvm::SmallPtrSet<llvm::BasicBlock * ,1> checkSet{branch->getParent()};
                    const llvm::SmallPtrSetImpl<llvm::BasicBlock *> *st = &checkSet; 

                    // newer versions of llvm let you go from blocks...
                    // TODO should pass loop info
                    bool canReachCTIWithoutCheckS0 = llvm::isPotentiallyReachable( branch->getSuccessor(0)->getFirstNonPHI(),firstCTIInsns,st,&this->DT);
                    bool canReachCTIWithoutCheckS1 = llvm::isPotentiallyReachable( branch->getSuccessor(1)->getFirstNonPHI(),firstCTIInsns,st, &this->DT);

                    if (canReachCTIWithoutCheckS0 && (! canReachCTIWithoutCheckS1)) {
                        return {{branch,true,branch->getSuccessor(1)}};
                    }

                    if ((!canReachCTIWithoutCheckS0) && canReachCTIWithoutCheckS1) {
                        return {{branch,false, branch->getSuccessor(0)}};
                    }
                }
                return std::nullopt;
            }

            bool runBoundsCheckPattern(const llvm::CallInst* intrinsicCall) {
                assert(this->index);
                auto taintedBranches = getTaintedBranches<10>(*this->index);
                auto dtNode = this->DT.getNode(intrinsicCall->getParent());
                auto inode = dtNode->getIDom()->getBlock();
                auto term = inode->getTerminator();
                auto maybe_bcheck = this->translateTerminatorToBoundsCheck(term, intrinsicCall->getParent());
                if (maybe_bcheck) {
                    auto bcheck = *maybe_bcheck;
                    this->defaultOut = {bcheck.failDirection};
                    auto cond = bcheck.branch->getCondition();
                    auto indexConstraints = ConstraintExtractor(*this->index).expectInsn(cond);

                    if(indexConstraints) {
                        auto cons = *indexConstraints;
                        if (!bcheck.passesCheckOnTrue) {
                            // we want the conditions s.t. the check passes
                            cons.logicalNot();
                        }

                        this->upperBound = cons.computeUB().getExclusiveMax();
                        return this->upperBound.has_value();
                    }

                }

                return false;
            }






            
           

        public:
            JumpTableDiscovery(const llvm::DominatorTree& DT, SliceManager& slices): pcRelSlice(std::nullopt), indexRelSlice(std::nullopt), index(std::nullopt), upperBound(std::nullopt), DT(DT), slices(slices)  {
            }




        // Definition a jump table bounds compare is a compare that uses the index and is used by a break that jumps to a block that may reach the indirect jump block or *must* not. the comparing block should dominate the indirect jump


        bool runIndexPattern(llvm::Value* pcarg) {
            Slicer pcrelSlicer;
            
            if (auto* pcinst = llvm::dyn_cast<llvm::Instruction>(pcarg)) {
                llvm::Value* stopPoint = pcrelSlicer.visit(pcinst);
                this->pcRelSlice = pcrelSlicer.getSlice();
                if (auto* loadFromJumpTable = llvm::dyn_cast<llvm::LoadInst>(stopPoint)) {
                    Slicer indexRelSlicer; 
                    this->loadedExpression = loadFromJumpTable->getOperand(0);
                    this->index = indexRelSlicer.checkInstruction(loadFromJumpTable->getOperand(0));
                    this->indexRelSlice = indexRelSlicer.getSlice();
                    return true;
                }
            }

            return false;
        }


        std::optional<JumpTableResult> runPattern(const llvm::CallInst* pcCall) {

            if( this->runIndexPattern(pcCall->getArgOperand(0)) && this->runBoundsCheckPattern(pcCall)) {
                SliceManager::SliceID pcRelId = this->slices.addSlice(*this->pcRelSlice, pcCall->getArgOperand(0));
                SliceManager::SliceID indexRelId = this->slices.addSlice(*this->indexRelSlice, *this->loadedExpression);
                PcRel pc(pcRelId);
                IndexRel indexRelation(indexRelId,*this->index);
                return  {{pc,indexRelation, *this->upperBound, *this->defaultOut}};
            }

            return std::nullopt;

        }  
    };

    



    std::optional<JumpTableResult> JumpTableAnalysis::getResultFor(llvm::CallInst* indirectJump) const {
        if (this->results.find(indirectJump) != this->results.end()) {
            return {this->results.find(indirectJump)->second};
        }

        return std::nullopt;
    }

    bool JumpTableAnalysis::runOnIndirectJump(llvm::CallInst* callinst) {
        auto const& DT = this->getAnalysis<llvm::DominatorTreeWrapperPass>().getDomTree();
        JumpTableDiscovery jtdisc(DT, this->slices);
        auto res = jtdisc.runPattern(callinst);
        if(res.has_value()) {
            this->results.insert({callinst,*res});
        }
        return false;
    }

    llvm::FunctionPass* CreateJumpTableAnalysis(SliceManager& slices) {
        return new JumpTableAnalysis(slices);
    }

      void JumpTableAnalysis::getAnalysisUsage(llvm::AnalysisUsage &AU) const {

        AU.setPreservesCFG(); // (ian) TODO in the future this will need to get removed when we eliminate the branch for table range checking.
        AU.addRequired<llvm::DominatorTreeWrapperPass>();
        AU.addRequired<llvm::InstructionCombiningPass>(); // needs instruction combiner to fold constants and order complexity
      }

      llvm::StringRef JumpTableAnalysis::getPassName() const {
          return "JumpTableAnalysis";
      }

}
        