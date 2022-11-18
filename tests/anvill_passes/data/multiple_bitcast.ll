; ModuleID = 'multiple_bitcast.ll'
source_filename = "llvm-link"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

%sub_400520.frame_type = type <{ i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64, i64, i64, i64, i8, i8, i8, i8, i32, i64, ptr }>
%sub_4003f0.frame_type = type <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr }>
%struct.State = type { %struct.ArchState, [32 x %union.VectorReg], %struct.ArithFlags, %union.anon, %struct.Segments, %struct.AddressSpace, %struct.GPR, %struct.X87Stack, %struct.MMX, %struct.FPUStatusFlags, %union.anon, %union.FPU, %struct.SegmentCaches }
%struct.ArchState = type { i32, i32, %union.anon }
%union.VectorReg = type { %union.vec512_t }
%union.vec512_t = type { %struct.uint64v8_t }
%struct.uint64v8_t = type { [8 x i64] }
%struct.ArithFlags = type { i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8 }
%struct.Segments = type { i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector, i16, %union.SegmentSelector }
%union.SegmentSelector = type { i16 }
%struct.AddressSpace = type { i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg }
%struct.Reg = type { %union.anon }
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
%struct.FpuFXSAVE = type { %union.SegmentSelector, %union.SegmentSelector, %union.FPUAbridgedTagWord, i8, i16, i32, %union.SegmentSelector, i16, i32, %union.SegmentSelector, i16, %union.FPUControlStatus, %union.FPUControlStatus, [8 x %struct.FPUStackElem], [16 x %union.vec128_t] }
%union.FPUAbridgedTagWord = type { i8 }
%union.FPUControlStatus = type { i32 }
%struct.FPUStackElem = type { %union.anon.11, [6 x i8] }
%union.anon.11 = type { %struct.float80_t }
%struct.float80_t = type { [10 x i8] }
%union.vec128_t = type { %struct.uint128v1_t }
%struct.uint128v1_t = type { [1 x i128] }
%struct.SegmentCaches = type { %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow }
%struct.SegmentShadow = type { %union.anon, i32, i32 }

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
@data_0 = local_unnamed_addr global [83 x i8] c"UH\89\E5H\83\ECPH\8D}\C8H\8DE\D0H\B9\10\06@\00\00\00\00\00\C7E\FC\00\00\00\00H\89\C2H\89}\C0H\89\D7H\89\CE\BA(\00\00\00H\89E\B8\E8\94\FE\FF\FFH\8BE\B8H\89E\C8H\8B}\C0\E8\83\FF\FF\FFH\83\C4P]\C3"

; Function Attrs: noduplicate noinline nounwind optnone
declare !remill.function.type !4 dso_local ptr @__remill_jump(ptr nonnull, i64, ptr) local_unnamed_addr #0

; Function Attrs: noinline
define i64 @valid_test(ptr %0) local_unnamed_addr #1 {
  %2 = bitcast ptr %0 to ptr
  %3 = load ptr, ptr %2, align 8
  %4 = getelementptr i8, ptr %3, i64 36
  %5 = bitcast ptr %4 to ptr
  %6 = load i32, ptr %5, align 4
  %7 = zext i32 %6 to i64
  ret i64 %7
}

; Function Attrs: noinline
define i32 @main(i32 %0, ptr %1, ptr %2) local_unnamed_addr #1 {
  %4 = call ptr @llvm.returnaddress(i32 0)
  %5 = alloca %sub_400520.frame_type, align 8
  %6 = getelementptr inbounds %sub_400520.frame_type, ptr %5, i64 0, i32 4
  %7 = getelementptr inbounds %sub_400520.frame_type, ptr %5, i64 0, i32 6
  %8 = getelementptr inbounds %sub_400520.frame_type, ptr %5, i64 0, i32 7
  %9 = getelementptr inbounds %sub_400520.frame_type, ptr %5, i64 0, i32 8
  %10 = ptrtoint ptr %9 to i64
  %11 = getelementptr inbounds %sub_400520.frame_type, ptr %5, i64 0, i32 9
  %12 = ptrtoint ptr %11 to i64
  %13 = getelementptr inbounds %sub_400520.frame_type, ptr %5, i64 0, i32 18
  %14 = getelementptr inbounds %sub_400520.frame_type, ptr %5, i64 0, i32 19
  %15 = getelementptr inbounds %sub_400520.frame_type, ptr %5, i64 0, i32 20
  %16 = load i64, ptr @__anvill_reg_RBP, align 8
  %17 = ptrtoint ptr %4 to i64
  %18 = bitcast ptr %15 to ptr
  store i64 %17, ptr %18, align 8
  store i64 %16, ptr %14, align 8
  store i32 0, ptr %13, align 4
  store i64 %10, ptr %8, align 8
  %19 = bitcast ptr %11 to ptr
  store i64 %12, ptr %7, align 8
  store i64 4195676, ptr %6, align 8
  %20 = call ptr @memcpy(ptr nonnull %19, ptr nonnull inttoptr (i64 4195856 to ptr), i64 40)
  %21 = load i64, ptr %7, align 8
  %22 = bitcast ptr %9 to ptr
  store i64 %21, ptr %22, align 8
  %23 = bitcast ptr %8 to ptr
  %24 = load ptr, ptr %23, align 8
  %25 = call i64 @valid_test(ptr %24)
  %26 = trunc i64 %25 to i32
  ret i32 %26
}

; Function Attrs: noinline
define ptr @memcpy(ptr %0, ptr %1, i64 %2) local_unnamed_addr #1 {
  %4 = call ptr @llvm.returnaddress(i32 0)
  %5 = alloca %sub_4003f0.frame_type, align 8
  %6 = getelementptr inbounds %sub_4003f0.frame_type, ptr %5, i64 0, i32 16
  %7 = ptrtoint ptr %6 to i64
  %8 = alloca %struct.State, align 8
  %9 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 1, i32 0, i32 0, !remill_register !5
  %10 = load i64, ptr @__anvill_reg_RAX, align 8
  store i64 %10, ptr %9, align 8
  %11 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 3, i32 0, i32 0, !remill_register !6
  %12 = load i64, ptr @__anvill_reg_RBX, align 8
  store i64 %12, ptr %11, align 8
  %13 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 5, i32 0, i32 0, !remill_register !7
  %14 = load i64, ptr @__anvill_reg_RCX, align 8
  store i64 %14, ptr %13, align 8
  %15 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 7, i32 0, i32 0, !remill_register !8
  %16 = load i64, ptr @__anvill_reg_RDX, align 8
  store i64 %16, ptr %15, align 8
  %17 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 9, i32 0, i32 0, !remill_register !9
  %18 = load i64, ptr @__anvill_reg_RSI, align 8
  store i64 %18, ptr %17, align 8
  %19 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 11, i32 0, i32 0, !remill_register !10
  %20 = load i64, ptr @__anvill_reg_RDI, align 8
  store i64 %20, ptr %19, align 8
  %21 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 13, i32 0, i32 0, !remill_register !11
  %22 = load i64, ptr @__anvill_reg_RSP, align 8
  store i64 %22, ptr %21, align 8
  %23 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 15, i32 0, i32 0, !remill_register !12
  %24 = load i64, ptr @__anvill_reg_RBP, align 8
  store i64 %24, ptr %23, align 8
  %25 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 33, i32 0, i32 0, !remill_register !13
  %26 = load i64, ptr @__anvill_reg_RIP, align 8
  store i64 %26, ptr %25, align 8
  %27 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 17, i32 0, i32 0, !remill_register !14
  %28 = load i64, ptr @__anvill_reg_R8, align 8
  store i64 %28, ptr %27, align 8
  %29 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 19, i32 0, i32 0, !remill_register !15
  %30 = load i64, ptr @__anvill_reg_R9, align 8
  store i64 %30, ptr %29, align 8
  %31 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 21, i32 0, i32 0, !remill_register !16
  %32 = load i64, ptr @__anvill_reg_R10, align 8
  store i64 %32, ptr %31, align 8
  %33 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 23, i32 0, i32 0, !remill_register !17
  %34 = load i64, ptr @__anvill_reg_R11, align 8
  store i64 %34, ptr %33, align 8
  %35 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 25, i32 0, i32 0, !remill_register !18
  %36 = load i64, ptr @__anvill_reg_R12, align 8
  store i64 %36, ptr %35, align 8
  %37 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 27, i32 0, i32 0, !remill_register !19
  %38 = load i64, ptr @__anvill_reg_R13, align 8
  store i64 %38, ptr %37, align 8
  %39 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 29, i32 0, i32 0, !remill_register !20
  %40 = load i64, ptr @__anvill_reg_R14, align 8
  store i64 %40, ptr %39, align 8
  %41 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 6, i32 31, i32 0, i32 0, !remill_register !21
  %42 = load i64, ptr @__anvill_reg_R15, align 8
  store i64 %42, ptr %41, align 8
  %43 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 4, i32 1, i32 0, !remill_register !22
  %44 = load i16, ptr @__anvill_reg_SS, align 2
  store i16 %44, ptr %43, align 2
  %45 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 4, i32 3, i32 0, !remill_register !23
  %46 = load i16, ptr @__anvill_reg_ES, align 2
  store i16 %46, ptr %45, align 2
  %47 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 4, i32 5, i32 0, !remill_register !24
  %48 = load i16, ptr @__anvill_reg_GS, align 2
  store i16 %48, ptr %47, align 2
  %49 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 4, i32 7, i32 0, !remill_register !25
  %50 = load i16, ptr @__anvill_reg_FS, align 2
  store i16 %50, ptr %49, align 2
  %51 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 4, i32 9, i32 0, !remill_register !26
  %52 = load i16, ptr @__anvill_reg_DS, align 2
  store i16 %52, ptr %51, align 2
  %53 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 4, i32 11, i32 0, !remill_register !27
  %54 = load i16, ptr @__anvill_reg_CS, align 2
  store i16 %54, ptr %53, align 2
  %55 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 5, i32 5, i32 0, i32 0, !remill_register !28
  %56 = load i64, ptr @__anvill_reg_GS_BASE, align 8
  store i64 %56, ptr %55, align 8
  %57 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 5, i32 7, i32 0, i32 0, !remill_register !29
  %58 = load i64, ptr @__anvill_reg_FS_BASE, align 8
  store i64 %58, ptr %57, align 8
  %59 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 0, i32 0, i32 0, i32 0, i64 0
  %60 = bitcast ptr %59 to ptr, !remill_register !30
  %.unpack = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 0), align 1
  %.unpack488 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 1), align 1
  %.unpack489 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 2), align 1
  %.unpack490 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 3), align 1
  %.unpack491 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 4), align 1
  %.unpack492 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 5), align 1
  %.unpack493 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 6), align 1
  %.unpack494 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 7), align 1
  %.unpack495 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 8), align 1
  %.unpack496 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 9), align 1
  %.unpack497 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 10), align 1
  %.unpack498 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 11), align 1
  %.unpack499 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 12), align 1
  %.unpack500 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 13), align 1
  %.unpack501 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 14), align 1
  %.unpack502 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM0, i64 0, i64 15), align 1
  %61 = bitcast ptr %59 to ptr
  store i8 %.unpack, ptr %61, align 8
  %62 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 1
  store i8 %.unpack488, ptr %62, align 1
  %63 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 2
  store i8 %.unpack489, ptr %63, align 2
  %64 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 3
  store i8 %.unpack490, ptr %64, align 1
  %65 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 4
  store i8 %.unpack491, ptr %65, align 4
  %66 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 5
  store i8 %.unpack492, ptr %66, align 1
  %67 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 6
  store i8 %.unpack493, ptr %67, align 2
  %68 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 7
  store i8 %.unpack494, ptr %68, align 1
  %69 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 0, i32 0, i32 0, i32 0, i64 1
  %70 = bitcast ptr %69 to ptr
  store i8 %.unpack495, ptr %70, align 8
  %71 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 9
  store i8 %.unpack496, ptr %71, align 1
  %72 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 10
  store i8 %.unpack497, ptr %72, align 2
  %73 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 11
  store i8 %.unpack498, ptr %73, align 1
  %74 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 12
  store i8 %.unpack499, ptr %74, align 4
  %75 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 13
  store i8 %.unpack500, ptr %75, align 1
  %76 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 14
  store i8 %.unpack501, ptr %76, align 2
  %77 = getelementptr inbounds [16 x i8], ptr %60, i64 0, i64 15
  store i8 %.unpack502, ptr %77, align 1
  %78 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 1, i32 0, i32 0, i32 0, i64 0
  %79 = bitcast ptr %78 to ptr, !remill_register !31
  %.unpack503 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 0), align 1
  %.unpack504 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 1), align 1
  %.unpack505 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 2), align 1
  %.unpack506 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 3), align 1
  %.unpack507 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 4), align 1
  %.unpack508 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 5), align 1
  %.unpack509 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 6), align 1
  %.unpack510 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 7), align 1
  %.unpack511 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 8), align 1
  %.unpack512 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 9), align 1
  %.unpack513 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 10), align 1
  %.unpack514 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 11), align 1
  %.unpack515 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 12), align 1
  %.unpack516 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 13), align 1
  %.unpack517 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 14), align 1
  %.unpack518 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM1, i64 0, i64 15), align 1
  %80 = bitcast ptr %78 to ptr
  store i8 %.unpack503, ptr %80, align 8
  %81 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 1
  store i8 %.unpack504, ptr %81, align 1
  %82 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 2
  store i8 %.unpack505, ptr %82, align 2
  %83 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 3
  store i8 %.unpack506, ptr %83, align 1
  %84 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 4
  store i8 %.unpack507, ptr %84, align 4
  %85 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 5
  store i8 %.unpack508, ptr %85, align 1
  %86 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 6
  store i8 %.unpack509, ptr %86, align 2
  %87 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 7
  store i8 %.unpack510, ptr %87, align 1
  %88 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 1, i32 0, i32 0, i32 0, i64 1
  %89 = bitcast ptr %88 to ptr
  store i8 %.unpack511, ptr %89, align 8
  %90 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 9
  store i8 %.unpack512, ptr %90, align 1
  %91 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 10
  store i8 %.unpack513, ptr %91, align 2
  %92 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 11
  store i8 %.unpack514, ptr %92, align 1
  %93 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 12
  store i8 %.unpack515, ptr %93, align 4
  %94 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 13
  store i8 %.unpack516, ptr %94, align 1
  %95 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 14
  store i8 %.unpack517, ptr %95, align 2
  %96 = getelementptr inbounds [16 x i8], ptr %79, i64 0, i64 15
  store i8 %.unpack518, ptr %96, align 1
  %97 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 2, i32 0, i32 0, i32 0, i64 0
  %98 = bitcast ptr %97 to ptr, !remill_register !32
  %.unpack519 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 0), align 1
  %.unpack520 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 1), align 1
  %.unpack521 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 2), align 1
  %.unpack522 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 3), align 1
  %.unpack523 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 4), align 1
  %.unpack524 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 5), align 1
  %.unpack525 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 6), align 1
  %.unpack526 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 7), align 1
  %.unpack527 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 8), align 1
  %.unpack528 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 9), align 1
  %.unpack529 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 10), align 1
  %.unpack530 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 11), align 1
  %.unpack531 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 12), align 1
  %.unpack532 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 13), align 1
  %.unpack533 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 14), align 1
  %.unpack534 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM2, i64 0, i64 15), align 1
  %99 = bitcast ptr %97 to ptr
  store i8 %.unpack519, ptr %99, align 8
  %100 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 1
  store i8 %.unpack520, ptr %100, align 1
  %101 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 2
  store i8 %.unpack521, ptr %101, align 2
  %102 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 3
  store i8 %.unpack522, ptr %102, align 1
  %103 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 4
  store i8 %.unpack523, ptr %103, align 4
  %104 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 5
  store i8 %.unpack524, ptr %104, align 1
  %105 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 6
  store i8 %.unpack525, ptr %105, align 2
  %106 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 7
  store i8 %.unpack526, ptr %106, align 1
  %107 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 2, i32 0, i32 0, i32 0, i64 1
  %108 = bitcast ptr %107 to ptr
  store i8 %.unpack527, ptr %108, align 8
  %109 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 9
  store i8 %.unpack528, ptr %109, align 1
  %110 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 10
  store i8 %.unpack529, ptr %110, align 2
  %111 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 11
  store i8 %.unpack530, ptr %111, align 1
  %112 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 12
  store i8 %.unpack531, ptr %112, align 4
  %113 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 13
  store i8 %.unpack532, ptr %113, align 1
  %114 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 14
  store i8 %.unpack533, ptr %114, align 2
  %115 = getelementptr inbounds [16 x i8], ptr %98, i64 0, i64 15
  store i8 %.unpack534, ptr %115, align 1
  %116 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 3, i32 0, i32 0, i32 0, i64 0
  %117 = bitcast ptr %116 to ptr, !remill_register !33
  %.unpack535 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 0), align 1
  %.unpack536 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 1), align 1
  %.unpack537 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 2), align 1
  %.unpack538 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 3), align 1
  %.unpack539 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 4), align 1
  %.unpack540 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 5), align 1
  %.unpack541 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 6), align 1
  %.unpack542 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 7), align 1
  %.unpack543 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 8), align 1
  %.unpack544 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 9), align 1
  %.unpack545 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 10), align 1
  %.unpack546 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 11), align 1
  %.unpack547 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 12), align 1
  %.unpack548 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 13), align 1
  %.unpack549 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 14), align 1
  %.unpack550 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM3, i64 0, i64 15), align 1
  %118 = bitcast ptr %116 to ptr
  store i8 %.unpack535, ptr %118, align 8
  %119 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 1
  store i8 %.unpack536, ptr %119, align 1
  %120 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 2
  store i8 %.unpack537, ptr %120, align 2
  %121 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 3
  store i8 %.unpack538, ptr %121, align 1
  %122 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 4
  store i8 %.unpack539, ptr %122, align 4
  %123 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 5
  store i8 %.unpack540, ptr %123, align 1
  %124 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 6
  store i8 %.unpack541, ptr %124, align 2
  %125 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 7
  store i8 %.unpack542, ptr %125, align 1
  %126 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 3, i32 0, i32 0, i32 0, i64 1
  %127 = bitcast ptr %126 to ptr
  store i8 %.unpack543, ptr %127, align 8
  %128 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 9
  store i8 %.unpack544, ptr %128, align 1
  %129 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 10
  store i8 %.unpack545, ptr %129, align 2
  %130 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 11
  store i8 %.unpack546, ptr %130, align 1
  %131 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 12
  store i8 %.unpack547, ptr %131, align 4
  %132 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 13
  store i8 %.unpack548, ptr %132, align 1
  %133 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 14
  store i8 %.unpack549, ptr %133, align 2
  %134 = getelementptr inbounds [16 x i8], ptr %117, i64 0, i64 15
  store i8 %.unpack550, ptr %134, align 1
  %135 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 4, i32 0, i32 0, i32 0, i64 0
  %136 = bitcast ptr %135 to ptr, !remill_register !34
  %.unpack551 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 0), align 1
  %.unpack552 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 1), align 1
  %.unpack553 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 2), align 1
  %.unpack554 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 3), align 1
  %.unpack555 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 4), align 1
  %.unpack556 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 5), align 1
  %.unpack557 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 6), align 1
  %.unpack558 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 7), align 1
  %.unpack559 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 8), align 1
  %.unpack560 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 9), align 1
  %.unpack561 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 10), align 1
  %.unpack562 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 11), align 1
  %.unpack563 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 12), align 1
  %.unpack564 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 13), align 1
  %.unpack565 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 14), align 1
  %.unpack566 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM4, i64 0, i64 15), align 1
  %137 = bitcast ptr %135 to ptr
  store i8 %.unpack551, ptr %137, align 8
  %138 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 1
  store i8 %.unpack552, ptr %138, align 1
  %139 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 2
  store i8 %.unpack553, ptr %139, align 2
  %140 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 3
  store i8 %.unpack554, ptr %140, align 1
  %141 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 4
  store i8 %.unpack555, ptr %141, align 4
  %142 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 5
  store i8 %.unpack556, ptr %142, align 1
  %143 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 6
  store i8 %.unpack557, ptr %143, align 2
  %144 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 7
  store i8 %.unpack558, ptr %144, align 1
  %145 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 4, i32 0, i32 0, i32 0, i64 1
  %146 = bitcast ptr %145 to ptr
  store i8 %.unpack559, ptr %146, align 8
  %147 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 9
  store i8 %.unpack560, ptr %147, align 1
  %148 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 10
  store i8 %.unpack561, ptr %148, align 2
  %149 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 11
  store i8 %.unpack562, ptr %149, align 1
  %150 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 12
  store i8 %.unpack563, ptr %150, align 4
  %151 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 13
  store i8 %.unpack564, ptr %151, align 1
  %152 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 14
  store i8 %.unpack565, ptr %152, align 2
  %153 = getelementptr inbounds [16 x i8], ptr %136, i64 0, i64 15
  store i8 %.unpack566, ptr %153, align 1
  %154 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 5, i32 0, i32 0, i32 0, i64 0
  %155 = bitcast ptr %154 to ptr, !remill_register !35
  %.unpack567 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 0), align 1
  %.unpack568 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 1), align 1
  %.unpack569 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 2), align 1
  %.unpack570 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 3), align 1
  %.unpack571 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 4), align 1
  %.unpack572 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 5), align 1
  %.unpack573 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 6), align 1
  %.unpack574 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 7), align 1
  %.unpack575 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 8), align 1
  %.unpack576 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 9), align 1
  %.unpack577 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 10), align 1
  %.unpack578 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 11), align 1
  %.unpack579 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 12), align 1
  %.unpack580 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 13), align 1
  %.unpack581 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 14), align 1
  %.unpack582 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM5, i64 0, i64 15), align 1
  %156 = bitcast ptr %154 to ptr
  store i8 %.unpack567, ptr %156, align 8
  %157 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 1
  store i8 %.unpack568, ptr %157, align 1
  %158 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 2
  store i8 %.unpack569, ptr %158, align 2
  %159 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 3
  store i8 %.unpack570, ptr %159, align 1
  %160 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 4
  store i8 %.unpack571, ptr %160, align 4
  %161 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 5
  store i8 %.unpack572, ptr %161, align 1
  %162 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 6
  store i8 %.unpack573, ptr %162, align 2
  %163 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 7
  store i8 %.unpack574, ptr %163, align 1
  %164 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 5, i32 0, i32 0, i32 0, i64 1
  %165 = bitcast ptr %164 to ptr
  store i8 %.unpack575, ptr %165, align 8
  %166 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 9
  store i8 %.unpack576, ptr %166, align 1
  %167 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 10
  store i8 %.unpack577, ptr %167, align 2
  %168 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 11
  store i8 %.unpack578, ptr %168, align 1
  %169 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 12
  store i8 %.unpack579, ptr %169, align 4
  %170 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 13
  store i8 %.unpack580, ptr %170, align 1
  %171 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 14
  store i8 %.unpack581, ptr %171, align 2
  %172 = getelementptr inbounds [16 x i8], ptr %155, i64 0, i64 15
  store i8 %.unpack582, ptr %172, align 1
  %173 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 6, i32 0, i32 0, i32 0, i64 0
  %174 = bitcast ptr %173 to ptr, !remill_register !36
  %.unpack583 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 0), align 1
  %.unpack584 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 1), align 1
  %.unpack585 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 2), align 1
  %.unpack586 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 3), align 1
  %.unpack587 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 4), align 1
  %.unpack588 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 5), align 1
  %.unpack589 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 6), align 1
  %.unpack590 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 7), align 1
  %.unpack591 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 8), align 1
  %.unpack592 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 9), align 1
  %.unpack593 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 10), align 1
  %.unpack594 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 11), align 1
  %.unpack595 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 12), align 1
  %.unpack596 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 13), align 1
  %.unpack597 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 14), align 1
  %.unpack598 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM6, i64 0, i64 15), align 1
  %175 = bitcast ptr %173 to ptr
  store i8 %.unpack583, ptr %175, align 8
  %176 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 1
  store i8 %.unpack584, ptr %176, align 1
  %177 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 2
  store i8 %.unpack585, ptr %177, align 2
  %178 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 3
  store i8 %.unpack586, ptr %178, align 1
  %179 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 4
  store i8 %.unpack587, ptr %179, align 4
  %180 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 5
  store i8 %.unpack588, ptr %180, align 1
  %181 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 6
  store i8 %.unpack589, ptr %181, align 2
  %182 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 7
  store i8 %.unpack590, ptr %182, align 1
  %183 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 6, i32 0, i32 0, i32 0, i64 1
  %184 = bitcast ptr %183 to ptr
  store i8 %.unpack591, ptr %184, align 8
  %185 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 9
  store i8 %.unpack592, ptr %185, align 1
  %186 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 10
  store i8 %.unpack593, ptr %186, align 2
  %187 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 11
  store i8 %.unpack594, ptr %187, align 1
  %188 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 12
  store i8 %.unpack595, ptr %188, align 4
  %189 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 13
  store i8 %.unpack596, ptr %189, align 1
  %190 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 14
  store i8 %.unpack597, ptr %190, align 2
  %191 = getelementptr inbounds [16 x i8], ptr %174, i64 0, i64 15
  store i8 %.unpack598, ptr %191, align 1
  %192 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 7, i32 0, i32 0, i32 0, i64 0
  %193 = bitcast ptr %192 to ptr, !remill_register !37
  %.unpack599 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 0), align 1
  %.unpack600 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 1), align 1
  %.unpack601 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 2), align 1
  %.unpack602 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 3), align 1
  %.unpack603 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 4), align 1
  %.unpack604 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 5), align 1
  %.unpack605 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 6), align 1
  %.unpack606 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 7), align 1
  %.unpack607 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 8), align 1
  %.unpack608 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 9), align 1
  %.unpack609 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 10), align 1
  %.unpack610 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 11), align 1
  %.unpack611 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 12), align 1
  %.unpack612 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 13), align 1
  %.unpack613 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 14), align 1
  %.unpack614 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM7, i64 0, i64 15), align 1
  %194 = bitcast ptr %192 to ptr
  store i8 %.unpack599, ptr %194, align 8
  %195 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 1
  store i8 %.unpack600, ptr %195, align 1
  %196 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 2
  store i8 %.unpack601, ptr %196, align 2
  %197 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 3
  store i8 %.unpack602, ptr %197, align 1
  %198 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 4
  store i8 %.unpack603, ptr %198, align 4
  %199 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 5
  store i8 %.unpack604, ptr %199, align 1
  %200 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 6
  store i8 %.unpack605, ptr %200, align 2
  %201 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 7
  store i8 %.unpack606, ptr %201, align 1
  %202 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 7, i32 0, i32 0, i32 0, i64 1
  %203 = bitcast ptr %202 to ptr
  store i8 %.unpack607, ptr %203, align 8
  %204 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 9
  store i8 %.unpack608, ptr %204, align 1
  %205 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 10
  store i8 %.unpack609, ptr %205, align 2
  %206 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 11
  store i8 %.unpack610, ptr %206, align 1
  %207 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 12
  store i8 %.unpack611, ptr %207, align 4
  %208 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 13
  store i8 %.unpack612, ptr %208, align 1
  %209 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 14
  store i8 %.unpack613, ptr %209, align 2
  %210 = getelementptr inbounds [16 x i8], ptr %193, i64 0, i64 15
  store i8 %.unpack614, ptr %210, align 1
  %211 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 8, i32 0, i32 0, i32 0, i64 0
  %212 = bitcast ptr %211 to ptr, !remill_register !38
  %.unpack615 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 0), align 1
  %.unpack616 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 1), align 1
  %.unpack617 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 2), align 1
  %.unpack618 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 3), align 1
  %.unpack619 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 4), align 1
  %.unpack620 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 5), align 1
  %.unpack621 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 6), align 1
  %.unpack622 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 7), align 1
  %.unpack623 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 8), align 1
  %.unpack624 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 9), align 1
  %.unpack625 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 10), align 1
  %.unpack626 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 11), align 1
  %.unpack627 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 12), align 1
  %.unpack628 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 13), align 1
  %.unpack629 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 14), align 1
  %.unpack630 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM8, i64 0, i64 15), align 1
  %213 = bitcast ptr %211 to ptr
  store i8 %.unpack615, ptr %213, align 8
  %214 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 1
  store i8 %.unpack616, ptr %214, align 1
  %215 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 2
  store i8 %.unpack617, ptr %215, align 2
  %216 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 3
  store i8 %.unpack618, ptr %216, align 1
  %217 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 4
  store i8 %.unpack619, ptr %217, align 4
  %218 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 5
  store i8 %.unpack620, ptr %218, align 1
  %219 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 6
  store i8 %.unpack621, ptr %219, align 2
  %220 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 7
  store i8 %.unpack622, ptr %220, align 1
  %221 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 8, i32 0, i32 0, i32 0, i64 1
  %222 = bitcast ptr %221 to ptr
  store i8 %.unpack623, ptr %222, align 8
  %223 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 9
  store i8 %.unpack624, ptr %223, align 1
  %224 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 10
  store i8 %.unpack625, ptr %224, align 2
  %225 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 11
  store i8 %.unpack626, ptr %225, align 1
  %226 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 12
  store i8 %.unpack627, ptr %226, align 4
  %227 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 13
  store i8 %.unpack628, ptr %227, align 1
  %228 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 14
  store i8 %.unpack629, ptr %228, align 2
  %229 = getelementptr inbounds [16 x i8], ptr %212, i64 0, i64 15
  store i8 %.unpack630, ptr %229, align 1
  %230 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 9, i32 0, i32 0, i32 0, i64 0
  %231 = bitcast ptr %230 to ptr, !remill_register !39
  %.unpack631 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 0), align 1
  %.unpack632 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 1), align 1
  %.unpack633 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 2), align 1
  %.unpack634 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 3), align 1
  %.unpack635 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 4), align 1
  %.unpack636 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 5), align 1
  %.unpack637 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 6), align 1
  %.unpack638 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 7), align 1
  %.unpack639 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 8), align 1
  %.unpack640 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 9), align 1
  %.unpack641 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 10), align 1
  %.unpack642 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 11), align 1
  %.unpack643 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 12), align 1
  %.unpack644 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 13), align 1
  %.unpack645 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 14), align 1
  %.unpack646 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM9, i64 0, i64 15), align 1
  %232 = bitcast ptr %230 to ptr
  store i8 %.unpack631, ptr %232, align 8
  %233 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 1
  store i8 %.unpack632, ptr %233, align 1
  %234 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 2
  store i8 %.unpack633, ptr %234, align 2
  %235 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 3
  store i8 %.unpack634, ptr %235, align 1
  %236 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 4
  store i8 %.unpack635, ptr %236, align 4
  %237 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 5
  store i8 %.unpack636, ptr %237, align 1
  %238 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 6
  store i8 %.unpack637, ptr %238, align 2
  %239 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 7
  store i8 %.unpack638, ptr %239, align 1
  %240 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 9, i32 0, i32 0, i32 0, i64 1
  %241 = bitcast ptr %240 to ptr
  store i8 %.unpack639, ptr %241, align 8
  %242 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 9
  store i8 %.unpack640, ptr %242, align 1
  %243 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 10
  store i8 %.unpack641, ptr %243, align 2
  %244 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 11
  store i8 %.unpack642, ptr %244, align 1
  %245 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 12
  store i8 %.unpack643, ptr %245, align 4
  %246 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 13
  store i8 %.unpack644, ptr %246, align 1
  %247 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 14
  store i8 %.unpack645, ptr %247, align 2
  %248 = getelementptr inbounds [16 x i8], ptr %231, i64 0, i64 15
  store i8 %.unpack646, ptr %248, align 1
  %249 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 10, i32 0, i32 0, i32 0, i64 0
  %250 = bitcast ptr %249 to ptr, !remill_register !40
  %.unpack647 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 0), align 1
  %.unpack648 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 1), align 1
  %.unpack649 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 2), align 1
  %.unpack650 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 3), align 1
  %.unpack651 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 4), align 1
  %.unpack652 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 5), align 1
  %.unpack653 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 6), align 1
  %.unpack654 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 7), align 1
  %.unpack655 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 8), align 1
  %.unpack656 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 9), align 1
  %.unpack657 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 10), align 1
  %.unpack658 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 11), align 1
  %.unpack659 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 12), align 1
  %.unpack660 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 13), align 1
  %.unpack661 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 14), align 1
  %.unpack662 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM10, i64 0, i64 15), align 1
  %251 = bitcast ptr %249 to ptr
  store i8 %.unpack647, ptr %251, align 8
  %252 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 1
  store i8 %.unpack648, ptr %252, align 1
  %253 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 2
  store i8 %.unpack649, ptr %253, align 2
  %254 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 3
  store i8 %.unpack650, ptr %254, align 1
  %255 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 4
  store i8 %.unpack651, ptr %255, align 4
  %256 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 5
  store i8 %.unpack652, ptr %256, align 1
  %257 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 6
  store i8 %.unpack653, ptr %257, align 2
  %258 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 7
  store i8 %.unpack654, ptr %258, align 1
  %259 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 10, i32 0, i32 0, i32 0, i64 1
  %260 = bitcast ptr %259 to ptr
  store i8 %.unpack655, ptr %260, align 8
  %261 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 9
  store i8 %.unpack656, ptr %261, align 1
  %262 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 10
  store i8 %.unpack657, ptr %262, align 2
  %263 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 11
  store i8 %.unpack658, ptr %263, align 1
  %264 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 12
  store i8 %.unpack659, ptr %264, align 4
  %265 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 13
  store i8 %.unpack660, ptr %265, align 1
  %266 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 14
  store i8 %.unpack661, ptr %266, align 2
  %267 = getelementptr inbounds [16 x i8], ptr %250, i64 0, i64 15
  store i8 %.unpack662, ptr %267, align 1
  %268 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 11, i32 0, i32 0, i32 0, i64 0
  %269 = bitcast ptr %268 to ptr, !remill_register !41
  %.unpack663 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 0), align 1
  %.unpack664 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 1), align 1
  %.unpack665 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 2), align 1
  %.unpack666 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 3), align 1
  %.unpack667 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 4), align 1
  %.unpack668 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 5), align 1
  %.unpack669 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 6), align 1
  %.unpack670 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 7), align 1
  %.unpack671 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 8), align 1
  %.unpack672 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 9), align 1
  %.unpack673 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 10), align 1
  %.unpack674 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 11), align 1
  %.unpack675 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 12), align 1
  %.unpack676 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 13), align 1
  %.unpack677 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 14), align 1
  %.unpack678 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM11, i64 0, i64 15), align 1
  %270 = bitcast ptr %268 to ptr
  store i8 %.unpack663, ptr %270, align 8
  %271 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 1
  store i8 %.unpack664, ptr %271, align 1
  %272 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 2
  store i8 %.unpack665, ptr %272, align 2
  %273 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 3
  store i8 %.unpack666, ptr %273, align 1
  %274 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 4
  store i8 %.unpack667, ptr %274, align 4
  %275 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 5
  store i8 %.unpack668, ptr %275, align 1
  %276 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 6
  store i8 %.unpack669, ptr %276, align 2
  %277 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 7
  store i8 %.unpack670, ptr %277, align 1
  %278 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 11, i32 0, i32 0, i32 0, i64 1
  %279 = bitcast ptr %278 to ptr
  store i8 %.unpack671, ptr %279, align 8
  %280 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 9
  store i8 %.unpack672, ptr %280, align 1
  %281 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 10
  store i8 %.unpack673, ptr %281, align 2
  %282 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 11
  store i8 %.unpack674, ptr %282, align 1
  %283 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 12
  store i8 %.unpack675, ptr %283, align 4
  %284 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 13
  store i8 %.unpack676, ptr %284, align 1
  %285 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 14
  store i8 %.unpack677, ptr %285, align 2
  %286 = getelementptr inbounds [16 x i8], ptr %269, i64 0, i64 15
  store i8 %.unpack678, ptr %286, align 1
  %287 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 12, i32 0, i32 0, i32 0, i64 0
  %288 = bitcast ptr %287 to ptr, !remill_register !42
  %.unpack679 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 0), align 1
  %.unpack680 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 1), align 1
  %.unpack681 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 2), align 1
  %.unpack682 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 3), align 1
  %.unpack683 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 4), align 1
  %.unpack684 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 5), align 1
  %.unpack685 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 6), align 1
  %.unpack686 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 7), align 1
  %.unpack687 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 8), align 1
  %.unpack688 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 9), align 1
  %.unpack689 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 10), align 1
  %.unpack690 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 11), align 1
  %.unpack691 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 12), align 1
  %.unpack692 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 13), align 1
  %.unpack693 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 14), align 1
  %.unpack694 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM12, i64 0, i64 15), align 1
  %289 = bitcast ptr %287 to ptr
  store i8 %.unpack679, ptr %289, align 8
  %290 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 1
  store i8 %.unpack680, ptr %290, align 1
  %291 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 2
  store i8 %.unpack681, ptr %291, align 2
  %292 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 3
  store i8 %.unpack682, ptr %292, align 1
  %293 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 4
  store i8 %.unpack683, ptr %293, align 4
  %294 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 5
  store i8 %.unpack684, ptr %294, align 1
  %295 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 6
  store i8 %.unpack685, ptr %295, align 2
  %296 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 7
  store i8 %.unpack686, ptr %296, align 1
  %297 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 12, i32 0, i32 0, i32 0, i64 1
  %298 = bitcast ptr %297 to ptr
  store i8 %.unpack687, ptr %298, align 8
  %299 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 9
  store i8 %.unpack688, ptr %299, align 1
  %300 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 10
  store i8 %.unpack689, ptr %300, align 2
  %301 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 11
  store i8 %.unpack690, ptr %301, align 1
  %302 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 12
  store i8 %.unpack691, ptr %302, align 4
  %303 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 13
  store i8 %.unpack692, ptr %303, align 1
  %304 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 14
  store i8 %.unpack693, ptr %304, align 2
  %305 = getelementptr inbounds [16 x i8], ptr %288, i64 0, i64 15
  store i8 %.unpack694, ptr %305, align 1
  %306 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 13, i32 0, i32 0, i32 0, i64 0
  %307 = bitcast ptr %306 to ptr, !remill_register !43
  %.unpack695 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 0), align 1
  %.unpack696 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 1), align 1
  %.unpack697 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 2), align 1
  %.unpack698 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 3), align 1
  %.unpack699 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 4), align 1
  %.unpack700 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 5), align 1
  %.unpack701 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 6), align 1
  %.unpack702 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 7), align 1
  %.unpack703 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 8), align 1
  %.unpack704 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 9), align 1
  %.unpack705 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 10), align 1
  %.unpack706 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 11), align 1
  %.unpack707 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 12), align 1
  %.unpack708 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 13), align 1
  %.unpack709 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 14), align 1
  %.unpack710 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM13, i64 0, i64 15), align 1
  %308 = bitcast ptr %306 to ptr
  store i8 %.unpack695, ptr %308, align 8
  %309 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 1
  store i8 %.unpack696, ptr %309, align 1
  %310 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 2
  store i8 %.unpack697, ptr %310, align 2
  %311 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 3
  store i8 %.unpack698, ptr %311, align 1
  %312 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 4
  store i8 %.unpack699, ptr %312, align 4
  %313 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 5
  store i8 %.unpack700, ptr %313, align 1
  %314 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 6
  store i8 %.unpack701, ptr %314, align 2
  %315 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 7
  store i8 %.unpack702, ptr %315, align 1
  %316 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 13, i32 0, i32 0, i32 0, i64 1
  %317 = bitcast ptr %316 to ptr
  store i8 %.unpack703, ptr %317, align 8
  %318 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 9
  store i8 %.unpack704, ptr %318, align 1
  %319 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 10
  store i8 %.unpack705, ptr %319, align 2
  %320 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 11
  store i8 %.unpack706, ptr %320, align 1
  %321 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 12
  store i8 %.unpack707, ptr %321, align 4
  %322 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 13
  store i8 %.unpack708, ptr %322, align 1
  %323 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 14
  store i8 %.unpack709, ptr %323, align 2
  %324 = getelementptr inbounds [16 x i8], ptr %307, i64 0, i64 15
  store i8 %.unpack710, ptr %324, align 1
  %325 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 14, i32 0, i32 0, i32 0, i64 0
  %326 = bitcast ptr %325 to ptr, !remill_register !44
  %.unpack711 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 0), align 1
  %.unpack712 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 1), align 1
  %.unpack713 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 2), align 1
  %.unpack714 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 3), align 1
  %.unpack715 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 4), align 1
  %.unpack716 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 5), align 1
  %.unpack717 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 6), align 1
  %.unpack718 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 7), align 1
  %.unpack719 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 8), align 1
  %.unpack720 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 9), align 1
  %.unpack721 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 10), align 1
  %.unpack722 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 11), align 1
  %.unpack723 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 12), align 1
  %.unpack724 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 13), align 1
  %.unpack725 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 14), align 1
  %.unpack726 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM14, i64 0, i64 15), align 1
  %327 = bitcast ptr %325 to ptr
  store i8 %.unpack711, ptr %327, align 8
  %328 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 1
  store i8 %.unpack712, ptr %328, align 1
  %329 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 2
  store i8 %.unpack713, ptr %329, align 2
  %330 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 3
  store i8 %.unpack714, ptr %330, align 1
  %331 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 4
  store i8 %.unpack715, ptr %331, align 4
  %332 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 5
  store i8 %.unpack716, ptr %332, align 1
  %333 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 6
  store i8 %.unpack717, ptr %333, align 2
  %334 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 7
  store i8 %.unpack718, ptr %334, align 1
  %335 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 14, i32 0, i32 0, i32 0, i64 1
  %336 = bitcast ptr %335 to ptr
  store i8 %.unpack719, ptr %336, align 8
  %337 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 9
  store i8 %.unpack720, ptr %337, align 1
  %338 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 10
  store i8 %.unpack721, ptr %338, align 2
  %339 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 11
  store i8 %.unpack722, ptr %339, align 1
  %340 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 12
  store i8 %.unpack723, ptr %340, align 4
  %341 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 13
  store i8 %.unpack724, ptr %341, align 1
  %342 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 14
  store i8 %.unpack725, ptr %342, align 2
  %343 = getelementptr inbounds [16 x i8], ptr %326, i64 0, i64 15
  store i8 %.unpack726, ptr %343, align 1
  %344 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 15, i32 0, i32 0, i32 0, i64 0
  %345 = bitcast ptr %344 to ptr, !remill_register !45
  %.unpack727 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 0), align 1
  %.unpack728 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 1), align 1
  %.unpack729 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 2), align 1
  %.unpack730 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 3), align 1
  %.unpack731 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 4), align 1
  %.unpack732 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 5), align 1
  %.unpack733 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 6), align 1
  %.unpack734 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 7), align 1
  %.unpack735 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 8), align 1
  %.unpack736 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 9), align 1
  %.unpack737 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 10), align 1
  %.unpack738 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 11), align 1
  %.unpack739 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 12), align 1
  %.unpack740 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 13), align 1
  %.unpack741 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 14), align 1
  %.unpack742 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_XMM15, i64 0, i64 15), align 1
  %346 = bitcast ptr %344 to ptr
  store i8 %.unpack727, ptr %346, align 8
  %347 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 1
  store i8 %.unpack728, ptr %347, align 1
  %348 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 2
  store i8 %.unpack729, ptr %348, align 2
  %349 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 3
  store i8 %.unpack730, ptr %349, align 1
  %350 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 4
  store i8 %.unpack731, ptr %350, align 4
  %351 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 5
  store i8 %.unpack732, ptr %351, align 1
  %352 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 6
  store i8 %.unpack733, ptr %352, align 2
  %353 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 7
  store i8 %.unpack734, ptr %353, align 1
  %354 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 1, i64 15, i32 0, i32 0, i32 0, i64 1
  %355 = bitcast ptr %354 to ptr
  store i8 %.unpack735, ptr %355, align 8
  %356 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 9
  store i8 %.unpack736, ptr %356, align 1
  %357 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 10
  store i8 %.unpack737, ptr %357, align 2
  %358 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 11
  store i8 %.unpack738, ptr %358, align 1
  %359 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 12
  store i8 %.unpack739, ptr %359, align 4
  %360 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 13
  store i8 %.unpack740, ptr %360, align 1
  %361 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 14
  store i8 %.unpack741, ptr %361, align 2
  %362 = getelementptr inbounds [16 x i8], ptr %345, i64 0, i64 15
  store i8 %.unpack742, ptr %362, align 1
  %363 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 7, i32 0, i64 0, i32 1, !remill_register !46
  %364 = load i64, ptr @__anvill_reg_ST0, align 8
  %365 = bitcast ptr %363 to ptr
  store i64 %364, ptr %365, align 8
  %366 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 7, i32 0, i64 1, i32 1, !remill_register !47
  %367 = load i64, ptr @__anvill_reg_ST1, align 8
  %368 = bitcast ptr %366 to ptr
  store i64 %367, ptr %368, align 8
  %369 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 7, i32 0, i64 2, i32 1, !remill_register !48
  %370 = load i64, ptr @__anvill_reg_ST2, align 8
  %371 = bitcast ptr %369 to ptr
  store i64 %370, ptr %371, align 8
  %372 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 7, i32 0, i64 3, i32 1, !remill_register !49
  %373 = load i64, ptr @__anvill_reg_ST3, align 8
  %374 = bitcast ptr %372 to ptr
  store i64 %373, ptr %374, align 8
  %375 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 7, i32 0, i64 4, i32 1, !remill_register !50
  %376 = load i64, ptr @__anvill_reg_ST4, align 8
  %377 = bitcast ptr %375 to ptr
  store i64 %376, ptr %377, align 8
  %378 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 7, i32 0, i64 5, i32 1, !remill_register !51
  %379 = load i64, ptr @__anvill_reg_ST5, align 8
  %380 = bitcast ptr %378 to ptr
  store i64 %379, ptr %380, align 8
  %381 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 7, i32 0, i64 6, i32 1, !remill_register !52
  %382 = load i64, ptr @__anvill_reg_ST6, align 8
  %383 = bitcast ptr %381 to ptr
  store i64 %382, ptr %383, align 8
  %384 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 7, i32 0, i64 7, i32 1, !remill_register !53
  %385 = load i64, ptr @__anvill_reg_ST7, align 8
  %386 = bitcast ptr %384 to ptr
  store i64 %385, ptr %386, align 8
  %387 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 8, i32 0, i64 0, i32 1, i32 0, i32 0, i64 0, !remill_register !54
  %388 = load i64, ptr @__anvill_reg_MM0, align 8
  store i64 %388, ptr %387, align 8
  %389 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 8, i32 0, i64 1, i32 1, i32 0, i32 0, i64 0, !remill_register !55
  %390 = load i64, ptr @__anvill_reg_MM1, align 8
  store i64 %390, ptr %389, align 8
  %391 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 8, i32 0, i64 2, i32 1, i32 0, i32 0, i64 0, !remill_register !56
  %392 = load i64, ptr @__anvill_reg_MM2, align 8
  store i64 %392, ptr %391, align 8
  %393 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 8, i32 0, i64 3, i32 1, i32 0, i32 0, i64 0, !remill_register !57
  %394 = load i64, ptr @__anvill_reg_MM3, align 8
  store i64 %394, ptr %393, align 8
  %395 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 8, i32 0, i64 4, i32 1, i32 0, i32 0, i64 0, !remill_register !58
  %396 = load i64, ptr @__anvill_reg_MM4, align 8
  store i64 %396, ptr %395, align 8
  %397 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 8, i32 0, i64 5, i32 1, i32 0, i32 0, i64 0, !remill_register !59
  %398 = load i64, ptr @__anvill_reg_MM5, align 8
  store i64 %398, ptr %397, align 8
  %399 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 8, i32 0, i64 6, i32 1, i32 0, i32 0, i64 0, !remill_register !60
  %400 = load i64, ptr @__anvill_reg_MM6, align 8
  store i64 %400, ptr %399, align 8
  %401 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 8, i32 0, i64 7, i32 1, i32 0, i32 0, i64 0, !remill_register !61
  %402 = load i64, ptr @__anvill_reg_MM7, align 8
  store i64 %402, ptr %401, align 8
  %403 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 2, i32 5, !remill_register !62
  %404 = load i8, ptr @__anvill_reg_AF, align 1
  store i8 %404, ptr %403, align 1
  %405 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 2, i32 1, !remill_register !63
  %406 = load i8, ptr @__anvill_reg_CF, align 1
  store i8 %406, ptr %405, align 1
  %407 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 2, i32 11, !remill_register !64
  %408 = load i8, ptr @__anvill_reg_DF, align 1
  store i8 %408, ptr %407, align 1
  %409 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 2, i32 13, !remill_register !65
  %410 = load i8, ptr @__anvill_reg_OF, align 1
  store i8 %410, ptr %409, align 1
  %411 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 2, i32 3, !remill_register !66
  %412 = load i8, ptr @__anvill_reg_PF, align 1
  store i8 %412, ptr %411, align 1
  %413 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 2, i32 9, !remill_register !67
  %414 = load i8, ptr @__anvill_reg_SF, align 1
  store i8 %414, ptr %413, align 1
  %415 = getelementptr inbounds %struct.State, ptr %8, i64 0, i32 2, i32 7, !remill_register !68
  %416 = load i8, ptr @__anvill_reg_ZF, align 1
  store i8 %416, ptr %415, align 1
  store i64 %7, ptr %21, align 8
  %417 = ptrtoint ptr %4 to i64
  %418 = bitcast ptr %6 to ptr
  store i64 %417, ptr %418, align 8
  %419 = ptrtoint ptr %0 to i64
  store i64 %419, ptr %19, align 8
  %420 = ptrtoint ptr %1 to i64
  store i64 %420, ptr %17, align 8
  store i64 %2, ptr %15, align 8
  %421 = load i64, ptr inttoptr (i64 6295576 to ptr), align 8
  store i64 %421, ptr %25, align 8, !alias.scope !69, !noalias !72
  %422 = call ptr @__remill_jump(ptr %8, i64 %421, ptr null)
  %423 = bitcast ptr %9 to ptr
  %424 = load ptr, ptr %423, align 8
  ret ptr %424
}

; Function Attrs: nofree nosync nounwind readnone willreturn
declare ptr @llvm.returnaddress(i32 immarg) #2

attributes #0 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { noinline }
attributes #2 = { nofree nosync nounwind readnone willreturn }

!llvm.ident = !{!0, !0, !0}
!llvm.module.flags = !{!1, !2, !3}
!llvm.dbg.cu = !{}

!0 = !{!"clang version 10.0.0 (https://github.com/microsoft/vcpkg.git ad2933e97e7f6d2e2bece2a7a372be7a6833f28c)"}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 7, !"Dwarf Version", i32 4}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{!"base.helper.semantics"}
!5 = !{[4 x i8] c"RAX\00"}
!6 = !{[4 x i8] c"RBX\00"}
!7 = !{[4 x i8] c"RCX\00"}
!8 = !{[4 x i8] c"RDX\00"}
!9 = !{[4 x i8] c"RSI\00"}
!10 = !{[4 x i8] c"RDI\00"}
!11 = !{[4 x i8] c"RSP\00"}
!12 = !{[4 x i8] c"RBP\00"}
!13 = !{[4 x i8] c"RIP\00"}
!14 = !{[3 x i8] c"R8\00"}
!15 = !{[3 x i8] c"R9\00"}
!16 = !{[4 x i8] c"R10\00"}
!17 = !{[4 x i8] c"R11\00"}
!18 = !{[4 x i8] c"R12\00"}
!19 = !{[4 x i8] c"R13\00"}
!20 = !{[4 x i8] c"R14\00"}
!21 = !{[4 x i8] c"R15\00"}
!22 = !{[3 x i8] c"SS\00"}
!23 = !{[3 x i8] c"ES\00"}
!24 = !{[3 x i8] c"GS\00"}
!25 = !{[3 x i8] c"FS\00"}
!26 = !{[3 x i8] c"DS\00"}
!27 = !{[3 x i8] c"CS\00"}
!28 = !{[8 x i8] c"GS_BASE\00"}
!29 = !{[8 x i8] c"FS_BASE\00"}
!30 = !{[5 x i8] c"XMM0\00"}
!31 = !{[5 x i8] c"XMM1\00"}
!32 = !{[5 x i8] c"XMM2\00"}
!33 = !{[5 x i8] c"XMM3\00"}
!34 = !{[5 x i8] c"XMM4\00"}
!35 = !{[5 x i8] c"XMM5\00"}
!36 = !{[5 x i8] c"XMM6\00"}
!37 = !{[5 x i8] c"XMM7\00"}
!38 = !{[5 x i8] c"XMM8\00"}
!39 = !{[5 x i8] c"XMM9\00"}
!40 = !{[6 x i8] c"XMM10\00"}
!41 = !{[6 x i8] c"XMM11\00"}
!42 = !{[6 x i8] c"XMM12\00"}
!43 = !{[6 x i8] c"XMM13\00"}
!44 = !{[6 x i8] c"XMM14\00"}
!45 = !{[6 x i8] c"XMM15\00"}
!46 = !{[4 x i8] c"ST0\00"}
!47 = !{[4 x i8] c"ST1\00"}
!48 = !{[4 x i8] c"ST2\00"}
!49 = !{[4 x i8] c"ST3\00"}
!50 = !{[4 x i8] c"ST4\00"}
!51 = !{[4 x i8] c"ST5\00"}
!52 = !{[4 x i8] c"ST6\00"}
!53 = !{[4 x i8] c"ST7\00"}
!54 = !{[4 x i8] c"MM0\00"}
!55 = !{[4 x i8] c"MM1\00"}
!56 = !{[4 x i8] c"MM2\00"}
!57 = !{[4 x i8] c"MM3\00"}
!58 = !{[4 x i8] c"MM4\00"}
!59 = !{[4 x i8] c"MM5\00"}
!60 = !{[4 x i8] c"MM6\00"}
!61 = !{[4 x i8] c"MM7\00"}
!62 = !{[3 x i8] c"AF\00"}
!63 = !{[3 x i8] c"CF\00"}
!64 = !{[3 x i8] c"DF\00"}
!65 = !{[3 x i8] c"OF\00"}
!66 = !{[3 x i8] c"PF\00"}
!67 = !{[3 x i8] c"SF\00"}
!68 = !{[3 x i8] c"ZF\00"}
!69 = !{!70}
!70 = distinct !{!70, !71, !"sub_4003f0.lifted: %state"}
!71 = distinct !{!71, !"sub_4003f0.lifted"}
!72 = !{!73}
!73 = distinct !{!73, !71, !"sub_4003f0.lifted: %memory"}
