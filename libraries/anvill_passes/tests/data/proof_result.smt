(declare-fun value1 () (_ BitVec 32))
(declare-fun value0 () (_ BitVec 32))
(declare-fun total_flag () Bool)
(declare-fun sign_flag () Bool)
(declare-fun overflow_flag () Bool)
(declare-fun condition () Bool)
(declare-fun value1neg () (_ BitVec 32))

(assert (= value1neg (bvxor value1 #xffffffff))) 

(assert (= sign_flag (bvslt ((_ extract 31 0)
                    (bvadd ((_ zero_extend 32) value1neg)
                           #x0000000000000001
                           ((_ zero_extend 32) value0)))
                  #x00000000)))


(assert (= overflow_flag       (distinct (bvashr (bvshl (bvadd ((_ zero_extend 32) value1neg)
                                 #x0000000000000001
                                 ((_ zero_extend 32) value0))
                          #x0000000000000020)
                   #x0000000000000020) (bvadd ((_ sign_extend 32) value1neg)
                                 #x0000000000000001
                                 ((_ sign_extend 32) value0)))))

(assert (= total_flag (= sign_flag
                overflow_flag)))


(assert (= condition (bvsge value0 value1) ))

(assert   (or (and condition (not total_flag))  (and total_flag (not condition))))

(check-sat)
(get-model)