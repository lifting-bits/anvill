; ModuleID = '/home/carson/work/remill/build/lib/Arch/X86/Runtime/amd64.bc'
source_filename = "llvm-link"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

; Function Attrs: noinline
define i32 @main(i32 %0, i8** %1, i8** %2) local_unnamed_addr #0 {
  br label %4

4:                                                ; preds = %13, %3
  %.sroa.3.0 = phi i32 [ 0, %3 ], [ %14, %13 ]
  %.sroa.0.0 = phi i32 [ 0, %3 ], [ %15, %13 ]
  %5 = add i32 %.sroa.0.0, -100
  %6 = lshr i32 %5, 31
  %7 = lshr i32 %.sroa.0.0, 31
  %8 = xor i32 %6, %7
  %9 = add nuw nsw i32 %8, %7
  %10 = icmp eq i32 %9, 2
  %11 = icmp sgt i32 %5, -1
  %12 = xor i1 %11, %10
  br i1 %12, label %16, label %13

13:                                               ; preds = %4
  %14 = add i32 %.sroa.3.0, 2
  %15 = add i32 %.sroa.0.0, 1
  br label %4

16:                                               ; preds = %4
  ret i32 %.sroa.3.0
}

attributes #0 = { noinline }

!llvm.ident = !{!0, !0, !0}
!llvm.module.flags = !{!1, !2, !3}
!llvm.dbg.cu = !{}

!0 = !{!"clang version 11.0.0 (https://github.com/trailofbits/vcpkg.git 4592a93cc4ca82f1963dba08413c43639662d7ae)"}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 7, !"Dwarf Version", i32 4}
!3 = !{i32 2, !"Debug Info Version", i32 3}
