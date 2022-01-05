; ModuleID = 'xor_conv_1.c'
source_filename = "xor_conv_1.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [13 x i8] c"f == false/0\00", align 1
@.str.1 = private unnamed_addr constant [12 x i8] c"f == true/1\00", align 1
@.str.2 = private unnamed_addr constant [47 x i8] c"this is a more complex branch for f == false/0\00", align 1
@.str.3 = private unnamed_addr constant [46 x i8] c"this is a more complex branch for f == true/1\00", align 1

; Function Attrs: nofree nounwind uwtable
define dso_local void @xor_as_not(i8* nocapture readonly %0, i8* nocapture %1) local_unnamed_addr #0 {
  %3 = getelementptr inbounds i8, i8* %0, i64 4
  %4 = load i8, i8* %3, align 1, !tbaa !2
  %5 = and i8 %4, 12
  %6 = icmp eq i8 %5, 0
  %7 = xor i1 %6, true
  %8 = zext i1 %7 to i8
  %9 = getelementptr inbounds i8, i8* %1, i64 5
  store i8 %8, i8* %9, align 1, !tbaa !2
  %10 = select i1 %6, i8* getelementptr inbounds ([12 x i8], [12 x i8]* @.str.1, i64 0, i64 0), i8* getelementptr inbounds ([13 x i8], [13 x i8]* @.str, i64 0, i64 0)
  %11 = call i32 @puts(i8* nonnull dereferenceable(1) %10)
  store i8 %8, i8* %9, align 1, !tbaa !2
  br i1 %6, label %18, label %12

12:                                               ; preds = %2
  %13 = call i32 @puts(i8* nonnull dereferenceable(1) getelementptr inbounds ([47 x i8], [47 x i8]* @.str.2, i64 0, i64 0))
  %14 = getelementptr inbounds i8, i8* %0, i64 12
  %15 = load i8, i8* %14, align 1, !tbaa !2
  %16 = load i8, i8* %3, align 1, !tbaa !2
  %17 = sub i8 %15, %16
  store i8 %17, i8* %1, align 1, !tbaa !2
  br label %21

18:                                               ; preds = %2
  %19 = call i32 @puts(i8* nonnull dereferenceable(1) getelementptr inbounds ([46 x i8], [46 x i8]* @.str.3, i64 0, i64 0))
  %20 = getelementptr inbounds i8, i8* %1, i64 1
  store i8 0, i8* %20, align 1, !tbaa !2
  br label %21

21:                                               ; preds = %18, %12
  ret void
}

; Function Attrs: nofree nounwind
declare dso_local i32 @puts(i8* nocapture readonly) local_unnamed_addr #1

attributes #0 = { nofree nounwind uwtable "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nofree nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"Debian clang version 11.1.0-++20210428103904+1fdec59bffc1-1~exp1~20210428204532.8"}
!2 = !{!3, !3, i64 0}
!3 = !{!"omnipotent char", !4, i64 0}
!4 = !{!"Simple C/C++ TBAA"}