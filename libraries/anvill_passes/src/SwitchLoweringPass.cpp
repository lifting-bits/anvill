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
#include <unordered_map>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

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


        bool isTargetInstrinsic(const llvm::CallInst* callinsn) {
            if (const auto *callee = callinsn->getCalledFunction()) {
                return callee->getName().equals(kAnvillSwitchCompleteFunc);
            }

            return false;
        }

        std::vector<llvm::CallInst*> getTargetCalls(llvm::Function &F) {
        std::vector<llvm::CallInst*> calls;
        for ( auto& blk: F.getBasicBlockList()) {
            for( auto& insn: blk.getInstList()) {
                llvm::Instruction* new_insn = &insn;
                if ( llvm::CallInst* call_insn = llvm::dyn_cast<llvm::CallInst>(new_insn)) {
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
                        LinearConstraint lcons(I.getPredicate(),newBound);
                        auto list = ConstraintList(lcons);
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



    struct PcRel {
        private:
            llvm::ConstantInt* programCounter;
            llvm::IntegerType* expectedInputType;

        public:
            PcRel( llvm::ConstantInt* programCounter, llvm::IntegerType* expectedInputType): programCounter(programCounter), expectedInputType(expectedInputType) {

            }


            llvm::APInt apply(llvm::APInt loadedTableValue) {
                return this->programCounter->getValue() + loadedTableValue;
            }

            llvm::IntegerType* getExpectedType() {
                return this->expectedInputType;
            }

    };

    enum CastType {ZEXT, SEXT, NONE};
    struct Cast {
        CastType caTy;
        unsigned int toBits;

        llvm::APInt apply(llvm::APInt target) {
            switch(this->caTy) {
                case CastType::ZEXT:
                    return target.zext(this->toBits);
                case CastType::SEXT:
                    return target.sext(this->toBits);
                case CastType::NONE:
                    return target;
            }
        }
    };

    

    struct IndexRel {
        private:
            llvm::ConstantInt* jumpTableAddr;
            llvm::APInt optWordSize;
            llvm::ConstantInt* normalizer;
            llvm::Value* index;
            Cast cast;


        public: 
            IndexRel(llvm::ConstantInt* jumpTableAddr, llvm::Value* index, llvm::ConstantInt* normalizer, llvm::APInt optWordSize, Cast cast): jumpTableAddr(jumpTableAddr), optWordSize(optWordSize), normalizer(normalizer), index(index), cast(cast) {
                assert(this->index != nullptr);
            }

            llvm::APInt apply(llvm::APInt index) {
                return this->jumpTableAddr->getValue() + (this->cast.apply(this->normalizer->getValue() + index) * this->optWordSize);
            }

            llvm::APInt getMinimumIndex() {
                assert(this->normalizer->getValue().isNegative() );
                return (-this->normalizer->getValue());
            }
            
            llvm::Value* getIndex() {
                return this->index;
            }
    };



    struct JumpTableResult {
        PcRel pcRel;
        IndexRel indexRel;
        llvm::APInt upperBound;
        llvm::BasicBlock* defaultOut;


        llvm::APInt getIndexMinimimum() {
            return this->indexRel.getMinimumIndex();
        }
    };


    class PcBinding {
        private:
            llvm::DenseMap<llvm::APInt, llvm::BasicBlock*> mapping;

            PcBinding(llvm::DenseMap<llvm::APInt, llvm::BasicBlock*> mapping): mapping(std::move(mapping)) {

            }


        public: 
            
            std::optional<llvm::BasicBlock*> lookup(llvm::APInt targetPc) const {
                if (this->mapping.find(targetPc) != this->mapping.end()) {
                    return {this->mapping.find(targetPc)->second};
                }

                return std::nullopt;
            }
            
            static PcBinding build(const llvm::CallInst* complete_switch, llvm::SwitchInst* follower) {
                assert(complete_switch->getNumArgOperands()-1==follower->getNumCases());

                llvm::DenseMap<llvm::APInt, llvm::BasicBlock*> mapping;
                for (auto caseHandler: follower->cases()) {
                    auto pcArg = complete_switch->getArgOperand(caseHandler.getCaseValue()->getValue().getLimitedValue()+1);// is the switch has more than 2^64 cases we have bigger problems
                    mapping.insert({llvm::cast<llvm::ConstantInt>(pcArg)->getValue(),caseHandler.getCaseSuccessor()});//  the argument to a complete switch should always be a constant int
                }

               return PcBinding(std::move(mapping));
            }
    };

    class JumpTableDiscovery {
        private:
            
            
            
            std::optional<PcRel> pcRel;
            std::optional<IndexRel> indexRel;
            std::optional<llvm::APInt> upperBound;
            std::optional<llvm::BasicBlock*> defaultOut;
            const llvm::DominatorTree& DT;
           

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
                assert(this->indexRel);
                auto taintedBranches = getTaintedBranches<10>(this->indexRel->getIndex());
                auto dtNode = this->DT.getNode(intrinsicCall->getParent());
                auto inode = dtNode->getIDom()->getBlock();
                auto term = inode->getTerminator();
                auto maybe_bcheck = this->translateTerminatorToBoundsCheck(term, intrinsicCall->getParent());
                if (maybe_bcheck) {
                    auto bcheck = *maybe_bcheck;
                    this->defaultOut = {bcheck.failDirection};
                    auto cond = bcheck.branch->getCondition();
                    auto indexConstraints = ConstraintExtractor(this->indexRel->getIndex()).expectInsn(cond);

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







            std::optional<llvm::Value*> extractPcRel(const llvm::Value* pcArg) {

                llvm::ConstantInt* potentialPc = nullptr;
                llvm::Value* potentialIndexPlusBaseExpr = nullptr;
                llvm::Value* load = nullptr;

                if (pats::match(pcArg,pats::m_Add(pats::m_Load(pats::m_Value(potentialIndexPlusBaseExpr)),pats::m_ConstantInt(potentialPc)))) {
                    assert(pats::match(pcArg,pats::m_Add(pats::m_Value(load),pats::m_Value())));
                    assert(load != nullptr);

                    if (auto *loadty = llvm::dyn_cast<llvm::IntegerType>(load->getType())) {
                        this->pcRel = {PcRel(potentialPc,loadty)};
                        return {potentialIndexPlusBaseExpr};
                    }
                }

                return nullptr;
            }



            bool extractIndexRel(const llvm::Value* indexPlusTableBase) {
                
                llvm::ConstantInt* shlfactor;
                llvm::ConstantInt* jumpTableAddr;
                llvm::Value* indexExpr;


                // TODO also try a pattern where Shl is a multiplication and SHL doesnt exist. Additionally, can replace this handcoding with interpretation.
                auto pat = pats::m_IntToPtr(
                            pats::m_Add(
                            pats::m_Shl(pats::m_Value(indexExpr),pats::m_ConstantInt(shlfactor)),
                                pats::m_ConstantInt(jumpTableAddr)));
                if (pats::match(indexPlusTableBase,pat)) {
     
                    // TODO handle case where there is no normalizer
                    llvm::Value* index = nullptr;
                    llvm::ConstantInt* normalizer = nullptr;

                    // ok tricky bit here is the index can be of any size up to word size really, turns out not so tricky 
                    auto indexAdd = pats::m_Add(pats::m_Value(index), pats::m_ConstantInt(normalizer));

                    
                    if(pats::match(indexExpr,pats::m_ZExtOrSExtOrSelf(indexAdd))) {
                        Cast cast = {CastType::NONE,indexExpr->getType()->getIntegerBitWidth()};
                        if (auto* zextOp = llvm::dyn_cast<llvm::ZExtInst>(indexExpr)) {
                            cast.toBits = zextOp->getDestTy()->getIntegerBitWidth();
                            cast.caTy = CastType::ZEXT;
                        }

                        if (auto* sextOp = llvm::dyn_cast<llvm::SExtInst>(indexExpr)) {
                            cast.toBits = sextOp->getDestTy()->getIntegerBitWidth();
                            cast.caTy = CastType::SEXT;
                        }


                        //normalizer has to be same bitwidth
                        auto optWordSize = llvm::APInt(cast.toBits, 1).shl(shlfactor->getValue());
                        this->indexRel = {IndexRel(jumpTableAddr,index,normalizer,optWordSize, cast)};
                        return true;
                    }

                }
                return false;

            }

            bool runIndexPattern(const llvm::Value* pcArg) {
                // this pattern could be screwed up by ordering of computation should have multiple cases at different stages
                // TODO figure out commuting (InstructionCombiner should kinda take care of this anyways)

                // to ensure this transformation is valid we now need to find the bounds check and ensure it lines up with the table.

                auto loadExpr = this->extractPcRel(pcArg);
                if (loadExpr) {
                    return this->extractIndexRel(*loadExpr);
                }

                return false;
            }
            
           

        public:
            JumpTableDiscovery(const llvm::DominatorTree& DT): pcRel(std::nullopt), indexRel(std::nullopt), upperBound(std::nullopt), DT(DT)  {
            }




        // Definition a jump table bounds compare is a compare that uses the index and is used by a break that jumps to a block that may reach the indirect jump block or *must* not. the comparing block should dominate the indirect jump


        std::optional<JumpTableResult> runPattern(const llvm::CallInst* pcCall) {

            if( this->runIndexPattern(pcCall->getArgOperand(0)) && this->runBoundsCheckPattern(pcCall)) {
                return  {{*this->pcRel,*this->indexRel, *this->upperBound, *this->defaultOut}};
            }

            return std::nullopt;

        }  
    };


    void SwitchLoweringPass::getAnalysisUsage(llvm::AnalysisUsage &AU) const {
        AU.setPreservesCFG(); // is this true?
        AU.addRequired<llvm::DominatorTreeWrapperPass>();
    
    }



    class SwitchBuilder {
    private:
        llvm::LLVMContext& context;
        const std::shared_ptr<MemoryProvider>& memProv;
        const llvm::DataLayout& dl;

        std::optional<llvm::APInt> readIntFrom(llvm::IntegerType* ty, llvm::APInt addr) {
            auto uaddr = addr.getLimitedValue();
            std::vector<uint8_t> memory;
            assert(ty->getBitWidth() % 8 == 0);
            auto target_bytes = ty->getBitWidth()/8;

            for (uint64_t i = 0; i < target_bytes; i++) {
                auto res = this->memProv->Query(uaddr+i);
                ByteAvailability avail = std::get<1>(res);
                if(avail != ByteAvailability::kAvailable) {
                    return std::nullopt;
                }
            
                memory.push_back(std::get<0>(res));
            }


            llvm::APInt res(ty->getBitWidth(), 0);


            // Endianess? may have to flip around memory as needed, yeah looks like LoadIntMemory loads at system memory so need to use flip_memory in llvm::endianess
            llvm::LoadIntFromMemory(res,memory.data(),target_bytes);

            if (this->dl.isLittleEndian() == llvm::sys::IsLittleEndianHost) {
                return res;
            } else {
                return res.byteSwap();
            }
        }
    public:
        SwitchBuilder(llvm::LLVMContext& context,  const std::shared_ptr<MemoryProvider>& memProv, const llvm::DataLayout& dl): context(context), memProv(memProv), dl(dl) {

        }

        std::optional<llvm::SwitchInst*> createNativeSwitch( JumpTableResult jt, const PcBinding& binding, llvm::LLVMContext& context) {
            auto minIndex = jt.getIndexMinimimum();
            auto numberOfCases = jt.upperBound-minIndex;
            llvm::SwitchInst* newSwitch = llvm::SwitchInst::Create(jt.indexRel.getIndex(),jt.defaultOut,numberOfCases.getLimitedValue());
            for(llvm::APInt currIndValue = minIndex; currIndValue.ult(jt.upperBound); currIndValue+=1) {
                auto readAddress = jt.indexRel.apply(currIndValue);
                std::optional<llvm::APInt> jmpOff = this->readIntFrom(jt.pcRel.getExpectedType(),readAddress);
                if (!jmpOff.has_value()) {
                    delete newSwitch;
                    return std::nullopt;
                } 

                auto newPc = jt.pcRel.apply(*jmpOff);
                auto outBlock = binding.lookup(newPc);
                if (!outBlock.has_value()) {
                    delete newSwitch;
                    return std::nullopt;
                } 


                if (*outBlock != jt.defaultOut) {
                    llvm::ConstantInt* indexVal = llvm::ConstantInt::get(this->context, currIndValue);
                    newSwitch->addCase(indexVal,*outBlock);  
                }
            }
            return newSwitch;
        }
    };

    bool SwitchLoweringPass::runOnFunction(llvm::Function &F) {
        auto dl = F.getParent()->getDataLayout();
        llvm::LLVMContext& context = F.getParent()->getContext();

        SwitchBuilder sbuilder(context, this->memProv, dl);
        auto targetCalls = getTargetCalls(F);
        const llvm::DominatorTree & DT = this->getAnalysis<llvm::DominatorTreeWrapperPass>().getDomTree();

        JumpTableDiscovery jumpDisc(DT);
        for(const auto& targetCall: targetCalls) {
            if (auto maybe_jresult = jumpDisc.runPattern(targetCall)) {
                auto jresult = *maybe_jresult;
                // so now that we've handled the recovering the switch structure need to go ahead and map the target switch 
                auto followingSwitch = targetCall->getParent()->getTerminator();
                auto follower = llvm::cast<llvm::SwitchInst>(followingSwitch);
                auto binding = PcBinding::build(targetCall, follower); 

                std::optional<llvm::SwitchInst*> newSwitch = sbuilder.createNativeSwitch(jresult,binding,context);
                if (newSwitch) {
                    llvm::ReplaceInstWithInst(follower, *newSwitch);
                }
                
            }
        }
        


        return false;
    }

    llvm::FunctionPass* CreateSwitchLoweringPass(std::shared_ptr<MemoryProvider> memProv) {
        return new SwitchLoweringPass(std::move(memProv));
    }

    llvm::StringRef SwitchLoweringPass::getPassName() const {
        return "SwitchLoweringPass";
    }

}