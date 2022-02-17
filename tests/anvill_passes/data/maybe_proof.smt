(declare-fun value1 () (_ BitVec 32))
(declare-fun value0 () (_ BitVec 32))
(assert (let ((a!1 ((_ extract 31 0)
             (bvadd ((_ zero_extend 32) (bvxor value1 #xffffffff))
                    #x0000000000000001
                    ((_ zero_extend 32) value0))))
      (a!2 (bvshl (bvadd ((_ zero_extend 32) (bvxor value1 #xffffffff))
                         #x0000000000000001
                         ((_ zero_extend 32) value0))
                  #x0000000000000020)))
(let ((a!3 (distinct (bvashr a!2 #x0000000000000020)
                     (bvadd ((_ sign_extend 32) (bvxor value1 #xffffffff))
                            #x0000000000000001
                            ((_ sign_extend 32) value0)))))
(let ((a!4 (and (bvsge value0 value1)
                (not (xor (bvslt a!1 #x00000000) a!3 (distinct #b1 #b0))))))
  (or a!4
      (and (xor (bvslt a!1 #x00000000) a!3 (distinct #b1 #b0))
           (not (bvsge value0 value1))))))))

(check-sat)