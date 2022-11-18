; ModuleID = 'RecoverSubBranch.ll'
source_filename = "lifted_code"
target datalayout = "e-m:o-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx-macho"

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_zero(i1 zeroext, ...) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_sign(i1 zeroext, ...) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_overflow(i1 zeroext, ...) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_compare_sle(i1 zeroext) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare i64 @__remill_read_memory_64(ptr, i64) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_function_return(ptr nonnull align 1, i64, ptr) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_missing_block(ptr nonnull align 1, i64, ptr) local_unnamed_addr #1

; Function Attrs: nounwind ssp
define ptr @slice(ptr %0, i64 %RAX, i64 %RDX, ptr nocapture %RIP_output) local_unnamed_addr #2 {
  %2 = sub i64 %RDX, %RAX
  %3 = icmp eq i64 %2, 0
  %4 = tail call zeroext i1 (i1, ...) @__remill_flag_computation_zero(i1 zeroext %3, i64 %RDX, i64 %RAX, i64 %2) #3
  %5 = icmp slt i64 %2, 0
  %6 = tail call zeroext i1 (i1, ...) @__remill_flag_computation_sign(i1 zeroext %5, i64 %RDX, i64 %RAX, i64 %2) #3
  %7 = lshr i64 %RDX, 63
  %8 = lshr i64 %RAX, 63
  %9 = lshr i64 %2, 63
  %10 = xor i64 %7, %8
  %11 = xor i64 %9, %7
  %12 = add nuw nsw i64 %11, %10
  %13 = icmp eq i64 %12, 2
  %14 = tail call zeroext i1 (i1, ...) @__remill_flag_computation_overflow(i1 zeroext %13, i64 %RDX, i64 %RAX, i64 %2) #3
  %15 = xor i1 %6, %14
  %16 = or i1 %4, %15
  %17 = tail call zeroext i1 @__remill_compare_sle(i1 zeroext %16) #4
  br i1 %17, label %18, label %21

18:                                               ; preds = %1
  %19 = tail call i64 @__remill_read_memory_64(ptr %0, i64 undef) #3
  %20 = tail call ptr @__remill_function_return(ptr undef, i64 %19, ptr %0) #5, !noalias !0
  br label %sub_0.exit

21:                                               ; preds = %1
  %22 = tail call ptr @__remill_missing_block(ptr undef, i64 8, ptr %0) #5, !noalias !0
  br label %sub_0.exit

sub_0.exit:                                       ; preds = %21, %18
  %.sroa.13.0 = phi i64 [ %19, %18 ], [ 8, %21 ]
  %23 = phi ptr [ %20, %18 ], [ %22, %21 ]
  store i64 %.sroa.13.0, ptr %RIP_output, align 8
  ret ptr %23
}

attributes #0 = { noduplicate noinline nounwind optnone readnone willreturn "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { noduplicate noinline nounwind optnone "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { nounwind ssp }
attributes #3 = { nobuiltin nounwind readnone willreturn "no-builtins" }
attributes #4 = { alwaysinline nobuiltin nounwind readnone willreturn "no-builtins" }
attributes #5 = { nounwind }

!0 = !{!1}
!1 = distinct !{!1, !2, !"sub_0: %state"}
!2 = distinct !{!2, !"sub_0"}
