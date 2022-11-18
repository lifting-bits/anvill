; ModuleID = 'BranchRecoveryAarch64.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "aarch64-apple-macosx-macho"

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_sign(i1 zeroext, ...) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_overflow(i1 zeroext, ...) local_unnamed_addr #0

; Function Attrs: nounwind readnone willreturn
declare zeroext i1 @__remill_compare_sge(i1 zeroext) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_function_return(ptr nonnull align 1, i64, ptr) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_missing_block(ptr nonnull align 1, i64, ptr) local_unnamed_addr #2

; Function Attrs: nounwind ssp
define ptr @slice(ptr %0, i32 %W10, i32 %W9, ptr nocapture %PC_output) local_unnamed_addr #3 {
  %.sroa.0.688.insert.ext = zext i32 %W9 to i64
  %2 = xor i32 %W10, -1
  %3 = zext i32 %2 to i64
  %4 = add nuw nsw i64 %3, 1
  %5 = add nuw nsw i64 %4, %.sroa.0.688.insert.ext
  %6 = sext i32 %W9 to i64
  %7 = sext i32 %2 to i64
  %8 = add nsw i64 %7, 1
  %9 = add nsw i64 %8, %6
  %10 = trunc i64 %5 to i32
  %11 = icmp slt i32 %10, 0
  %12 = tail call zeroext i1 (i1, ...) @__remill_flag_computation_sign(i1 zeroext %11, i32 %W9, i32 %W10, i32 %10) #4
  %13 = shl i64 %5, 32
  %14 = ashr exact i64 %13, 32
  %15 = icmp ne i64 %14, %9
  %16 = tail call zeroext i1 (i1, ...) @__remill_flag_computation_overflow(i1 zeroext %15, i32 %W9, i32 %W10, i32 %10) #4
  %17 = xor i1 %12, %16
  %18 = xor i1 %17, true
  %19 = tail call zeroext i1 @__remill_compare_sge(i1 zeroext %18) #4
  br i1 %19, label %20, label %22

20:                                               ; preds = %1
  %21 = tail call ptr @__remill_function_return(ptr undef, i64 undef, ptr %0) #5, !noalias !0
  br label %sub_0.exit

22:                                               ; preds = %1
  %23 = tail call ptr @__remill_missing_block(ptr undef, i64 16, ptr %0) #5, !noalias !0
  br label %sub_0.exit

sub_0.exit:                                       ; preds = %22, %20
  %24 = phi ptr [ %21, %20 ], [ %23, %22 ]
  store i64 16, ptr %PC_output, align 8
  ret ptr %24
}

attributes #0 = { noduplicate noinline nounwind optnone readnone willreturn "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone willreturn "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind ssp }
attributes #4 = { nobuiltin nounwind readnone willreturn "no-builtins" }
attributes #5 = { nounwind }

!0 = !{!1}
!1 = distinct !{!1, !2, !"sub_0: %state"}
!2 = distinct !{!2, !"sub_0"}
