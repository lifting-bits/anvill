; ModuleID = '/home/carson/work/remill/build/lib/Arch/X86/Runtime/amd64.bc'
source_filename = "llvm-link"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

@__anvill_reg_RAX = local_unnamed_addr global i64 0
@__anvill_reg_RBX = local_unnamed_addr global i64 0
@__anvill_reg_RCX = local_unnamed_addr global i64 0
@__anvill_reg_RDX = local_unnamed_addr global i64 0
@__anvill_reg_RSI = local_unnamed_addr global i64 0
@__anvill_reg_RDI = local_unnamed_addr global i64 0
@__anvill_reg_RSP = local_unnamed_addr global i64 0
@__anvill_reg_RBP = local_unnamed_addr global i64 0
@__anvill_reg_RIP = local_unnamed_addr global i64 0
@__anvill_reg_R8 = local_unnamed_addr global i64 0
@__anvill_reg_R9 = local_unnamed_addr global i64 0
@__anvill_reg_R10 = local_unnamed_addr global i64 0
@__anvill_reg_R11 = local_unnamed_addr global i64 0
@__anvill_reg_R12 = local_unnamed_addr global i64 0
@__anvill_reg_R13 = local_unnamed_addr global i64 0
@__anvill_reg_R14 = local_unnamed_addr global i64 0
@__anvill_reg_R15 = local_unnamed_addr global i64 0
@__anvill_reg_SS = local_unnamed_addr global i16 0
@__anvill_reg_ES = local_unnamed_addr global i16 0
@__anvill_reg_GS = local_unnamed_addr global i16 0
@__anvill_reg_FS = local_unnamed_addr global i16 0
@__anvill_reg_DS = local_unnamed_addr global i16 0
@__anvill_reg_CS = local_unnamed_addr global i16 0
@__anvill_reg_GS_BASE = local_unnamed_addr global i64 0
@__anvill_reg_FS_BASE = local_unnamed_addr global i64 0
@__anvill_reg_XMM0 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM1 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM2 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM3 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM4 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM5 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM6 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM7 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM8 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM9 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM10 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM11 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM12 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM13 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM14 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM15 = local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_ST0 = local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST1 = local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST2 = local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST3 = local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST4 = local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST5 = local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST6 = local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST7 = local_unnamed_addr global double 0.000000e+00
@__anvill_reg_MM0 = local_unnamed_addr global i64 0
@__anvill_reg_MM1 = local_unnamed_addr global i64 0
@__anvill_reg_MM2 = local_unnamed_addr global i64 0
@__anvill_reg_MM3 = local_unnamed_addr global i64 0
@__anvill_reg_MM4 = local_unnamed_addr global i64 0
@__anvill_reg_MM5 = local_unnamed_addr global i64 0
@__anvill_reg_MM6 = local_unnamed_addr global i64 0
@__anvill_reg_MM7 = local_unnamed_addr global i64 0
@__anvill_reg_AF = local_unnamed_addr global i8 0
@__anvill_reg_CF = local_unnamed_addr global i8 0
@__anvill_reg_DF = local_unnamed_addr global i8 0
@__anvill_reg_OF = local_unnamed_addr global i8 0
@__anvill_reg_PF = local_unnamed_addr global i8 0
@__anvill_reg_SF = local_unnamed_addr global i8 0
@__anvill_reg_ZF = local_unnamed_addr global i8 0

; Function Attrs: noinline
define i32 @main(i32 %0, i8** %1, i8** %2) local_unnamed_addr #0 {
  %4 = load i64, i64* inttoptr (i64 6295600 to i64*), align 16
  %5 = add i64 %4, 128
  %6 = inttoptr i64 %5 to i32*
  %7 = load i32, i32* %6, align 4
  ret i32 %7
}

attributes #0 = { noinline }

!llvm.ident = !{!0, !0, !0}
!llvm.module.flags = !{!1, !2, !3}
!llvm.dbg.cu = !{}

!0 = !{!"clang version 10.0.0 (https://github.com/microsoft/vcpkg.git ad2933e97e7f6d2e2bece2a7a372be7a6833f28c)"}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 7, !"Dwarf Version", i32 4}
!3 = !{i32 2, !"Debug Info Version", i32 3}
