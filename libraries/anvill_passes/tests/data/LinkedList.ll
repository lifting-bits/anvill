; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "aarch64-apple-macosx-macho"

@var_50__Cbx1_D = external global [1 x i8]
@__anvill_reg_X0 = internal local_unnamed_addr global i64 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@llvm.compiler.used = appending global [2 x i8*] [i8* bitcast (i64 ()* @sub_0__Avl_B_0 to i8*), i8* getelementptr inbounds ([1 x i8], [1 x i8]* @var_50__Cbx1_D, i32 0, i32 0)], section "llvm.metadata"
@__anvill_stack_minus_8 = global i8 0
@__anvill_stack_minus_7 = global i8 0
@__anvill_stack_minus_6 = global i8 0
@__anvill_stack_minus_5 = global i8 0
@__anvill_stack_minus_4 = global i8 0
@__anvill_stack_minus_3 = global i8 0
@__anvill_stack_minus_2 = global i8 0
@__anvill_stack_minus_1 = global i8 0

; Function Attrs: noinline
define i64 @sub_0__Avl_B_0() #0 {
  %1 = load i64, i64* @__anvill_reg_X0, align 8
  br label %2

2:                                                ; preds = %4, %0
  %storemerge = phi i64 [ 80, %0 ], [ %6, %4 ]
  %3 = icmp eq i64 %storemerge, 0
  br i1 %3, label %7, label %4

4:                                                ; preds = %2
  %5 = inttoptr i64 %storemerge to i64*
  %6 = load i64, i64* %5, align 8
  br label %2

7:                                                ; preds = %2
  ret i64 %1
}

attributes #0 = { noinline }
