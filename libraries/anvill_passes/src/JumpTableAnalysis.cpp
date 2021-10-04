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
#include <z3++.h>


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
    }

    namespace pats = llvm::PatternMatch;

    struct BoundsCheck {
        const llvm::BranchInst* branch;
        bool passesCheckOnTrue;
        llvm::BasicBlock* failDirection;
    };

    class Expr {
        public:
            virtual ~Expr();
            virtual z3::expr build_expression(z3::context& c, z3::expr indexExpr) const = 0;
    };

    class AtomIndexExpr final: public Expr {

        public:

            z3::expr build_expression(z3::context& c, z3::expr indexExpr) const override {
                return indexExpr;
            }

            static std::unique_ptr<Expr> Create() {
                return std::make_unique<AtomIndexExpr>();
            }
    };

    class AtomIntExpr final: public Expr {
        private:
            llvm::APInt atomValue;


        static std::unique_ptr<bool[]> getBigEndianBits(llvm::APInt api) {
            llvm::APInt togetBitsFrom = api;
            if (llvm::sys::IsLittleEndianHost) {
                // we are storing in little endian but z3 is big endian so
                togetBitsFrom = api.byteSwap();
            } 

            auto res = std::make_unique<bool[]>(togetBitsFrom.getBitWidth());
            for (unsigned int i = 0; i < api.getBitWidth(); i++) {
                res[i] = togetBitsFrom[i];
            }

            return res;
        }
        
        public:
            AtomIntExpr(llvm::APInt atomValue): atomValue(atomValue) {}

            z3::expr build_expression(z3::context& c, z3::expr indexExpr) const override {
                auto bv_width = this->atomValue.getBitWidth();
                auto bv_bits = AtomIntExpr::getBigEndianBits(this->atomValue);
                return c.bv_val(bv_width,bv_bits.get());
            }

            static std::unique_ptr<Expr> Create(llvm::APInt value) {
                return std::make_unique<AtomIntExpr>(value);
            }
    };

    // might be able to combine complex formula with binop tbh
    // this technically allows (x /\ y) + (a /\ b) should maybe prevent these from being constructed, currently relies on the visitor to check and not construct.
    enum Z3Binop {ADD, ULE,ULT, UGT, UGE, AND, OR, EQ};
    class BinopExpr final: public Expr {
        private:
            Z3Binop opcode;
            std::unique_ptr<Expr> lhs;
            std::unique_ptr<Expr> rhs;
        
        public:
        
            BinopExpr(Z3Binop opcode, std::unique_ptr<Expr> lhs , std::unique_ptr<Expr> rhs) : opcode(opcode), lhs(std::move(lhs)), rhs(std::move(rhs)) {}


            static std::unique_ptr<Expr> Create(Z3Binop opcode, std::unique_ptr<Expr> lhs , std::unique_ptr<Expr> rhs) {
                return std::make_unique<BinopExpr>(opcode, std::move(lhs), std::move(rhs));
            }
    
            z3::expr build_expression(z3::context& c, z3::expr indexExpr) const override {
                auto e1 = this->lhs->build_expression(c,indexExpr);
                auto e2 = this->rhs->build_expression(c,indexExpr);
                switch(this->opcode) {
                    case ADD:
                        return z3::operator+(e1, e2);
                    case ULE:
                        return z3::ule(e1, e2); 
                    case ULT:
                        return z3::ult(e1, e2);
                    case UGT:
                        return z3::ugt(e1, e2);
                    case UGE:
                        return z3::uge(e1, e2);
                    case EQ:
                        return z3::operator==(e1, e2);
                    default:
                        throw std::invalid_argument("unknown opcode binop");
                }
            }
    };

    enum Z3Unop {LOGNOT};
    class UnopExpr final: public Expr {
        private:
            Z3Unop opcode;
            std::unique_ptr<Expr> lhs;

        public:
            
            UnopExpr( Z3Unop opcode, std::unique_ptr<Expr> lhs): opcode(opcode), lhs(std::move(lhs)) {

            }

            static std::unique_ptr<Expr> Create(Z3Unop opcode, std::unique_ptr<Expr> lhs) {
                return std::make_unique<UnopExpr>(opcode, std::move(lhs));
            }

            z3::expr build_expression(z3::context& c, z3::expr indexExpr) const override {
                auto e1 = this->lhs->build_expression(c,indexExpr);
                switch(this->opcode) {
                    case Z3Unop::LOGNOT:
                        return z3::operator!(e1);
                    default:
                        throw std::invalid_argument("unknown opcode unop");
                }
            }   
    };


    class ExprSolve {
        private:
        
            std::optional<llvm::APInt> optomizeExpr(const std::unique_ptr<Expr>& exp,llvm::Value* index, std::function<z3::expr(z3::optimize, z3::expr)> getoptimal) {
                    z3::context c;
                    z3::expr index_bv = c.bv_const("index", index->getType()->getIntegerBitWidth());
                    z3::expr constraints = exp->build_expression(c, index_bv);  
                    z3::optimize s(c);
                    s.add(constraints);

                    if (z3::sat == s.check()) {
                        z3::expr res = getoptimal(s,index_bv);
                        return llvm::APInt(index->getType()->getIntegerBitWidth(), res.as_uint64());
                    } else {
                        return std::nullopt;
                    }
            }

        public:
            std::optional<llvm::APInt> solveForUB(const std::unique_ptr<Expr>& exp,llvm::Value* index) {
                return this->optomizeExpr(exp, index, [](z3::optimize o, z3::expr target_bv) -> z3::expr {
                    z3::optimize::handle h = o.maximize(target_bv);
                    return o.upper(h);
                });
            }

            std::optional<llvm::APInt> solveForLB(const std::unique_ptr<Expr>& exp,llvm::Value* index) {
                return this->optomizeExpr(exp, index, [](z3::optimize o, z3::expr target_bv) -> z3::expr {
                    z3::optimize::handle h = o.minimize(target_bv);
                    return o.lower(h);
                });
            }      
    };  
    

    // core assumption currently constraints are treated as unsigned
    class ConstraintExtractor: public llvm::InstVisitor<ConstraintExtractor,std::optional<std::unique_ptr<Expr>>> {
        private:


            static std::optional<Z3Binop> translateOpcodeToConnective(llvm::Instruction::BinaryOps op) {
                switch (op)
                {
                case llvm::Instruction::BinaryOps::And /* constant-expression */:
                    /* code */
                    return {Z3Binop::AND};
                case llvm::Instruction::BinaryOps::Or:
                    return {Z3Binop::OR};
                case llvm::Instruction::BinaryOps::Add:
                    return {Z3Binop::ADD};
                default:
                    return std::nullopt;
                }
            }


            static std::optional<Z3Binop> translateICMPOpToZ3(llvm::CmpInst::Predicate op) {
                switch (op)
                {
                case llvm::CmpInst::Predicate::ICMP_EQ:
                    return Z3Binop::EQ;
                case llvm::CmpInst::Predicate::ICMP_UGE:
                    return Z3Binop::UGE;
                case llvm::CmpInst::Predicate::ICMP_UGT:
                    return Z3Binop::UGT;
                case llvm::CmpInst::Predicate::ICMP_ULE:
                    return Z3Binop::ULE;
                case llvm::CmpInst::Predicate::ICMP_ULT:
                    return Z3Binop::ULT;
                default:
                    return std::nullopt;
                }
            }



            const llvm::Value* index;


        public: 

            std::optional<std::unique_ptr<Expr>> expectInsnOrIndex(llvm::Value* v) {
                if (v == this->index) {
                    return AtomIndexExpr::Create();
                }

                if (auto* constint = llvm::dyn_cast<llvm::ConstantInt>(v)) {
                    return AtomIntExpr::Create(constint->getValue());
                }
                
                if (auto* insn = llvm::dyn_cast<llvm::Instruction>(v)) {
                    return this->visit(*insn);
                }

            

                return std::nullopt;
            }


            ConstraintExtractor(const llvm::Value* index): index(index) {}


            std::optional<std::unique_ptr<Expr>> visitInstruction(llvm::Instruction &I ) {
                return std::nullopt;
            }

            std::optional<std::unique_ptr<Expr>> visitICmpInst(llvm::ICmpInst &I) {
                auto conn = translateICMPOpToZ3(I.getPredicate());


                if (auto repr0 = this->expectInsnOrIndex(I.getOperand(0))) {
                    if (auto repr1 = this->expectInsnOrIndex(I.getOperand(1))) {
                        if (conn) {
                            return {BinopExpr::Create(*conn,std::move(*repr0), std::move(*repr1))};
                        }
                    }
                }

                return std::nullopt;
            }

            std::optional<std::unique_ptr<Expr>>  visitBinaryOperator(llvm::BinaryOperator &B) {
                auto conn = translateOpcodeToConnective(B.getOpcode());


                if (auto repr0 = this->expectInsnOrIndex(B.getOperand(0))) {
                    if (auto repr1 = this->expectInsnOrIndex(B.getOperand(1))) {
                        if (conn) {
                            return {BinopExpr::Create(*conn,std::move(*repr0), std::move(*repr1))};
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
            std::optional<llvm::APInt> upperBound; //inclusive
            std::optional<llvm::APInt> lowerBound; //inclusive
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
                    std::optional<std::unique_ptr<Expr>> indexConstraints = ConstraintExtractor(*this->index).expectInsnOrIndex(cond);

                    if(indexConstraints) {
                        std::unique_ptr<Expr> cons = std::move(*indexConstraints);
                        if (!bcheck.passesCheckOnTrue) {
                            // we want the conditions s.t. the check passes
                            cons = UnopExpr::Create(Z3Unop::LOGNOT,std::move(cons));
                        }

                        ExprSolve s;

                        this->upperBound = s.solveForUB(cons,*this->index);
                        this->lowerBound = s.solveForLB(cons, *this->index);
                        return this->upperBound.has_value() && this->lowerBound.has_value();
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
                return  {{pc,indexRelation, *this->upperBound, *this->lowerBound, *this->defaultOut}};
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
        