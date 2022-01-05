; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"
target triple = "i386-pc-linux-gnu-elf"

%struct.Memory = type opaque
%struct.State = type { %struct.ArchState, [32 x %union.VectorReg], %struct.ArithFlags, %union.anon, %struct.Segments, %struct.AddressSpace, %struct.GPR, %struct.X87Stack, %struct.MMX, %struct.FPUStatusFlags, %union.anon, %union.FPU, %struct.SegmentCaches }
%struct.ArchState = type { i32, i32, %union.anon }
%union.VectorReg = type { %union.vec512_t }
%union.vec512_t = type { %struct.uint64v8_t }
%struct.uint64v8_t = type { [8 x i64] }
%struct.ArithFlags = type { i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8 }
%struct.Segments = type { i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector }
%union.SegmentSelector = type { i16 }
%struct.AddressSpace = type { i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg }
%struct.Reg = type { %union.anon.1, i32 }
%union.anon.1 = type { i32 }
%struct.GPR = type { i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg }
%struct.X87Stack = type { [8 x %struct.anon.3] }
%struct.anon.3 = type { i64, double }
%struct.MMX = type { [8 x %struct.anon.4] }
%struct.anon.4 = type { i64, %union.vec64_t }
%union.vec64_t = type { %struct.uint64v1_t }
%struct.uint64v1_t = type { [1 x i64] }
%struct.FPUStatusFlags = type { i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, [4 x i8] }
%union.anon = type { i64 }
%union.FPU = type { %struct.anon.13 }
%struct.anon.13 = type { %struct.FpuFXSAVE, [96 x i8] }
%struct.FpuFXSAVE = type { %union.SegmentSelector, %union.SegmentSelector, %union.FPUAbridgedTagWord, i8, i16, i32, %union.SegmentSelector, i16, i32, %union.SegmentSelector, i16, %union.anon.1, %union.anon.1, [8 x %struct.FPUStackElem], [16 x %union.vec128_t] }
%union.FPUAbridgedTagWord = type { i8 }
%struct.FPUStackElem = type { %union.anon.11, [6 x i8] }
%union.anon.11 = type { %struct.float80_t }
%struct.float80_t = type { [10 x i8] }
%union.vec128_t = type { %struct.uint128v1_t }
%struct.uint128v1_t = type { [1 x i128] }
%struct.SegmentCaches = type { %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow }
%struct.SegmentShadow = type { %union.anon, i32, i32 }

@__anvill_sp = external global i8
@__anvill_ra = external global i8
@__anvill_pc = external global i8

; Function Attrs: noinline
declare i32 @sub_80483f0__Ai_Sii_B_0(i32, i32*) local_unnamed_addr #0

; Function Attrs: noinline
define i32 @sub_80482e0__Ai_S_Sb_S_Sbi_B_0(i32 %0, i8** %1, i8** %2) local_unnamed_addr #0 {
  store i32 ptrtoint (i8* @__anvill_ra to i32), i32* inttoptr (i32 ptrtoint (i8* @__anvill_sp to i32) to i32*), align 4
  store i32 %0, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 4) to i32*), align 4
  %4 = ptrtoint i8** %1 to i32
  store i32 %4, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 8) to i32*), align 4
  %5 = ptrtoint i8** %2 to i32
  store i32 %5, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 12) to i32*), align 4
  %6 = load i32, i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 20) to i32*), align 4
  store i32 %6, i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 12) to i32*), align 4
  store i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 12), i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 -4) to i32*), align 4
  store i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 12), i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 -8) to i32*), align 4
  store i32 add (i32 ptrtoint (i8* @__anvill_pc to i32), i32 134513398), i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 -12) to i32*), align 4
  %7 = load i32, i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 -8) to i32*), align 4
  %8 = load i32, i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 -4) to i32*), align 4
  %9 = inttoptr i32 %8 to i32*
  %10 = call i32 @sub_80483f0__Ai_Sii_B_0(i32 %7, i32* %9)
  %11 = load i32, i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 16) to i32*), align 4
  %12 = call %struct.Memory* @__remill_function_return(%struct.State* undef, i32 %11, %struct.Memory* null)
  ret i32 %10
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_32(%struct.Memory*, i32, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i32 @__remill_read_memory_32(%struct.Memory*, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local %struct.Memory* @__remill_function_return(%struct.State* nonnull align 1, i32, %struct.Memory*) local_unnamed_addr #2

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }