; ModuleID = 'RegressionRecoverStack.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"
target triple = "i386-pc-linux-gnu-elf"

@__anvill_sp = external global i8
@__anvill_ra = external global i8
@__anvill_pc = external global i8

declare zeroext i1 @__remill_flag_computation_sign(i1 zeroext, ...) local_unnamed_addr

define i1 @slice() local_unnamed_addr {
  %1 = call zeroext i1 (i1, ...) @__remill_flag_computation_sign(i1 zeroext icmp slt (i32 add (i32 ptrtoint (ptr @__anvill_sp to i32), i32 -12), i32 0), i32 add (i32 ptrtoint (ptr @__anvill_sp to i32), i32 -12))
  ret i1 %1
}
