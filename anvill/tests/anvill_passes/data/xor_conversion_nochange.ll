; ModuleID = 'xor_conv_2.c'
source_filename = "xor_conv_2.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: nofree norecurse nounwind uwtable
define dso_local void @xor_as_not_nochange(i8* nocapture readonly %0, i8* nocapture %1) local_unnamed_addr #0 {
  %3 = getelementptr inbounds i8, i8* %0, i64 4
  %4 = load i8, i8* %3, align 1, !tbaa !2
  %5 = and i8 %4, 12
  %6 = icmp eq i8 %5, 0
  %7 = zext i1 %6 to i8
  %8 = xor i1 %6, true
  %9 = zext i1 %8 to i8
  %10 = getelementptr inbounds i8, i8* %1, i64 5
  store i8 %9, i8* %10, align 1, !tbaa !2
  %11 = getelementptr inbounds i8, i8* %1, i64 1
  store i8 %7, i8* %11, align 1, !tbaa !2
  %12 = zext i1 %6 to i64
  %13 = getelementptr inbounds i8, i8* %0, i64 %12
  %14 = load i8, i8* %13, align 1, !tbaa !2
  %15 = add i8 %14, 1
  store i8 %15, i8* %1, align 1, !tbaa !2
  %16 = getelementptr inbounds i8, i8* %1, i64 3
  store i8 %9, i8* %16, align 1, !tbaa !2
  ret void
}

attributes #0 = { nofree norecurse nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"Debian clang version 11.1.0-++20210428103904+1fdec59bffc1-1~exp1~20210428204532.8"}
!2 = !{!3, !3, i64 0}
!3 = !{!"omnipotent char", !4, i64 0}
!4 = !{!"Simple C/C++ TBAA"}