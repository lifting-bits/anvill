; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"
target triple = "i386-pc-linux-gnu-elf"

%sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type = type <{ [44 x i8] }>
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
@llvm.compiler.used = appending global [2 x i8*] [i8* bitcast (i32 (i32, i8**, i8**)* @sub_80482e0__Ai_S_Sb_S_Sbi_B_0 to i8*), i8* bitcast (i32 (i32, i32*)* @sub_80483f0__Ai_Sii_B_0 to i8*)], section "llvm.metadata"
@__anvill_stack_minus_28 = global i8 0
@__anvill_stack_minus_27 = global i8 0
@__anvill_stack_minus_26 = global i8 0
@__anvill_stack_minus_25 = global i8 0
@__anvill_stack_minus_24 = global i8 0
@__anvill_stack_minus_23 = global i8 0
@__anvill_stack_minus_22 = global i8 0
@__anvill_stack_minus_21 = global i8 0
@__anvill_stack_minus_20 = global i8 0
@__anvill_stack_minus_19 = global i8 0
@__anvill_stack_minus_18 = global i8 0
@__anvill_stack_minus_17 = global i8 0
@__anvill_stack_minus_16 = global i8 0
@__anvill_stack_minus_15 = global i8 0
@__anvill_stack_minus_14 = global i8 0
@__anvill_stack_minus_13 = global i8 0
@__anvill_stack_minus_12 = global i8 0
@__anvill_stack_minus_11 = global i8 0
@__anvill_stack_minus_10 = global i8 0
@__anvill_stack_minus_9 = global i8 0
@__anvill_stack_minus_8 = global i8 0
@__anvill_stack_minus_7 = global i8 0
@__anvill_stack_minus_6 = global i8 0
@__anvill_stack_minus_5 = global i8 0
@__anvill_stack_minus_4 = global i8 0
@__anvill_stack_minus_3 = global i8 0
@__anvill_stack_minus_2 = global i8 0
@__anvill_stack_minus_1 = global i8 0
@__anvill_stack_0 = global i8 0
@__anvill_stack_plus_1 = global i8 0
@__anvill_stack_plus_2 = global i8 0
@__anvill_stack_plus_3 = global i8 0
@__anvill_stack_plus_4 = global i8 0
@__anvill_stack_plus_5 = global i8 0
@__anvill_stack_plus_6 = global i8 0
@__anvill_stack_plus_7 = global i8 0
@__anvill_stack_plus_8 = global i8 0
@__anvill_stack_plus_9 = global i8 0
@__anvill_stack_plus_10 = global i8 0
@__anvill_stack_plus_11 = global i8 0
@__anvill_stack_plus_12 = global i8 0
@__anvill_stack_plus_13 = global i8 0
@__anvill_stack_plus_14 = global i8 0
@__anvill_stack_plus_15 = global i8 0

; Function Attrs: noinline
declare i32 @sub_80483f0__Ai_Sii_B_0(i32, i32*) #0

; Function Attrs: noinline
define i32 @sub_80482e0__Ai_S_Sb_S_Sbi_B_0(i32 %0, i8** %1, i8** %2) #0 {
  %4 = alloca %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, align 8
  %5 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 0
  %6 = load i8, i8* @__anvill_stack_minus_28, align 1
  store i8 %6, i8* %5, align 1
  %7 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 1
  %8 = load i8, i8* @__anvill_stack_minus_27, align 1
  store i8 %8, i8* %7, align 1
  %9 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 2
  %10 = load i8, i8* @__anvill_stack_minus_26, align 1
  store i8 %10, i8* %9, align 1
  %11 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 3
  %12 = load i8, i8* @__anvill_stack_minus_25, align 1
  store i8 %12, i8* %11, align 1
  %13 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 4
  %14 = load i8, i8* @__anvill_stack_minus_24, align 1
  store i8 %14, i8* %13, align 1
  %15 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 5
  %16 = load i8, i8* @__anvill_stack_minus_23, align 1
  store i8 %16, i8* %15, align 1
  %17 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 6
  %18 = load i8, i8* @__anvill_stack_minus_22, align 1
  store i8 %18, i8* %17, align 1
  %19 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 7
  %20 = load i8, i8* @__anvill_stack_minus_21, align 1
  store i8 %20, i8* %19, align 1
  %21 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 8
  %22 = load i8, i8* @__anvill_stack_minus_20, align 1
  store i8 %22, i8* %21, align 1
  %23 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 9
  %24 = load i8, i8* @__anvill_stack_minus_19, align 1
  store i8 %24, i8* %23, align 1
  %25 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 10
  %26 = load i8, i8* @__anvill_stack_minus_18, align 1
  store i8 %26, i8* %25, align 1
  %27 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 11
  %28 = load i8, i8* @__anvill_stack_minus_17, align 1
  store i8 %28, i8* %27, align 1
  %29 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 12
  %30 = load i8, i8* @__anvill_stack_minus_16, align 1
  store i8 %30, i8* %29, align 1
  %31 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 13
  %32 = load i8, i8* @__anvill_stack_minus_15, align 1
  store i8 %32, i8* %31, align 1
  %33 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 14
  %34 = load i8, i8* @__anvill_stack_minus_14, align 1
  store i8 %34, i8* %33, align 1
  %35 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 15
  %36 = load i8, i8* @__anvill_stack_minus_13, align 1
  store i8 %36, i8* %35, align 1
  %37 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 16
  %38 = load i8, i8* @__anvill_stack_minus_12, align 1
  store i8 %38, i8* %37, align 1
  %39 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 17
  %40 = load i8, i8* @__anvill_stack_minus_11, align 1
  store i8 %40, i8* %39, align 1
  %41 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 18
  %42 = load i8, i8* @__anvill_stack_minus_10, align 1
  store i8 %42, i8* %41, align 1
  %43 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 19
  %44 = load i8, i8* @__anvill_stack_minus_9, align 1
  store i8 %44, i8* %43, align 1
  %45 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 20
  %46 = load i8, i8* @__anvill_stack_minus_8, align 1
  store i8 %46, i8* %45, align 1
  %47 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 21
  %48 = load i8, i8* @__anvill_stack_minus_7, align 1
  store i8 %48, i8* %47, align 1
  %49 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 22
  %50 = load i8, i8* @__anvill_stack_minus_6, align 1
  store i8 %50, i8* %49, align 1
  %51 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 23
  %52 = load i8, i8* @__anvill_stack_minus_5, align 1
  store i8 %52, i8* %51, align 1
  %53 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 24
  %54 = load i8, i8* @__anvill_stack_minus_4, align 1
  store i8 %54, i8* %53, align 1
  %55 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 25
  %56 = load i8, i8* @__anvill_stack_minus_3, align 1
  store i8 %56, i8* %55, align 1
  %57 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 26
  %58 = load i8, i8* @__anvill_stack_minus_2, align 1
  store i8 %58, i8* %57, align 1
  %59 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 27
  %60 = load i8, i8* @__anvill_stack_minus_1, align 1
  store i8 %60, i8* %59, align 1
  %61 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 28
  %62 = load i8, i8* @__anvill_stack_0, align 1
  store i8 %62, i8* %61, align 1
  %63 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 29
  %64 = load i8, i8* @__anvill_stack_plus_1, align 1
  store i8 %64, i8* %63, align 1
  %65 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 30
  %66 = load i8, i8* @__anvill_stack_plus_2, align 1
  store i8 %66, i8* %65, align 1
  %67 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 31
  %68 = load i8, i8* @__anvill_stack_plus_3, align 1
  store i8 %68, i8* %67, align 1
  %69 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 32
  %70 = load i8, i8* @__anvill_stack_plus_4, align 1
  store i8 %70, i8* %69, align 1
  %71 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 33
  %72 = load i8, i8* @__anvill_stack_plus_5, align 1
  store i8 %72, i8* %71, align 1
  %73 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 34
  %74 = load i8, i8* @__anvill_stack_plus_6, align 1
  store i8 %74, i8* %73, align 1
  %75 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 35
  %76 = load i8, i8* @__anvill_stack_plus_7, align 1
  store i8 %76, i8* %75, align 1
  %77 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 36
  %78 = load i8, i8* @__anvill_stack_plus_8, align 1
  store i8 %78, i8* %77, align 1
  %79 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 37
  %80 = load i8, i8* @__anvill_stack_plus_9, align 1
  store i8 %80, i8* %79, align 1
  %81 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 38
  %82 = load i8, i8* @__anvill_stack_plus_10, align 1
  store i8 %82, i8* %81, align 1
  %83 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 39
  %84 = load i8, i8* @__anvill_stack_plus_11, align 1
  store i8 %84, i8* %83, align 1
  %85 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 40
  %86 = load i8, i8* @__anvill_stack_plus_12, align 1
  store i8 %86, i8* %85, align 1
  %87 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 41
  %88 = load i8, i8* @__anvill_stack_plus_13, align 1
  store i8 %88, i8* %87, align 1
  %89 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 42
  %90 = load i8, i8* @__anvill_stack_plus_14, align 1
  store i8 %90, i8* %89, align 1
  %91 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 43
  %92 = load i8, i8* @__anvill_stack_plus_15, align 1
  store i8 %92, i8* %91, align 1
  %93 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 28
  %94 = bitcast i8* %93 to i32*
  store i32 ptrtoint (i8* @__anvill_ra to i32), i32* %94, align 4
  %95 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 32
  %96 = bitcast i8* %95 to i32*
  store i32 %0, i32* %96, align 4
  %97 = ptrtoint i8** %1 to i32
  %98 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 36
  %99 = bitcast i8* %98 to i32*
  store i32 %97, i32* %99, align 4
  %100 = ptrtoint i8** %2 to i32
  %101 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 40
  %102 = bitcast i8* %101 to i32*
  store i32 %100, i32* %102, align 4
  %103 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 32
  %104 = bitcast i8* %103 to i32*
  %105 = load i32, i32* %104, align 4
  %106 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 24
  %107 = bitcast i8* %106 to i32*
  store i32 %105, i32* %107, align 4
  %108 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 24
  %109 = ptrtoint i8* %108 to i32
  %110 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 8
  %111 = bitcast i8* %110 to i32*
  store i32 %109, i32* %111, align 4
  %112 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 24
  %113 = ptrtoint i8* %112 to i32
  %114 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 4
  %115 = bitcast i8* %114 to i32*
  store i32 %113, i32* %115, align 4
  %116 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 0
  %117 = bitcast i8* %116 to i32*
  store i32 add (i32 ptrtoint (i8* @__anvill_pc to i32), i32 134513398), i32* %117, align 4
  %118 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 4
  %119 = bitcast i8* %118 to i32*
  %120 = load i32, i32* %119, align 4
  %121 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 8
  %122 = bitcast i8* %121 to i32*
  %123 = load i32, i32* %122, align 4
  %124 = inttoptr i32 %123 to i32*
  %125 = call i32 @sub_80483f0__Ai_Sii_B_0(i32 %120, i32* %124)
  %126 = getelementptr %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %4, i32 0, i32 0, i32 28
  %127 = bitcast i8* %126 to i32*
  %128 = load i32, i32* %127, align 4
  %129 = call %struct.Memory* @__remill_function_return(%struct.State* undef, i32 %128, %struct.Memory* null)
  ret i32 %125
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