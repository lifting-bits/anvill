; ModuleID = 'SplitStackFrameAtReturnAddress.bc'
source_filename = "lifted_code"
target datalayout = "e-m:e-p:32:32-p270:32:32-p271:32:32-p272:64:64-f64:32:64-f80:32-n8:16:32-S128"
target triple = "i386-pc-linux-gnu-elf"

%sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type = type <{ i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32*, i32*, i32*, i32, i32, i32, i32*, i32*, i32*, i32*, i32* }>
%sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type = type <{ i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32*, i32*, i32*, i32, i32, i32, i32*, i32*, i32*, i32*, i32* }>
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

@data_80482e0 = global [26 x i8] c"\83\EC\10\8BD$\14\89D$\0C\8DD$\0CPP\E8\FA\00\00\00\83\C4\18\C3"

; Function Attrs: noinline
declare i32 @sub_80483f0__Ai_Sii_B_0(i32, i32*) local_unnamed_addr #0

; Function Attrs: noinline
define i32 @sub_80482e0__Ai_S_Sb_S_Sbi_B_0(i32 %0, i8** %1, i8** %2) local_unnamed_addr #0 {
  %4 = call i8* @llvm.returnaddress(i32 0)
  %5 = alloca %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, align 8
  %6 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %5, i32 0, i32 25
  %7 = bitcast i32** %6 to i32*
  %8 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %5, i32 0, i32 26
  %9 = bitcast i32** %8 to i32*
  %10 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %5, i32 0, i32 27
  %11 = bitcast i32** %10 to i32*
  %12 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %5, i32 0, i32 31
  %13 = bitcast i32** %12 to i32*
  %14 = ptrtoint i32** %12 to i32
  %15 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %5, i32 0, i32 32
  %16 = bitcast i32** %15 to i32*
  %17 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %5, i32 0, i32 33
  %18 = bitcast i32** %17 to i32*
  %19 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %5, i32 0, i32 34
  %20 = bitcast i32** %19 to i32*
  %21 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0.frame_type* %5, i32 0, i32 35
  %22 = bitcast i32** %21 to i32*
  %23 = ptrtoint i8* %4 to i32
  store i32 %23, i32* %16, align 8
  store i32 %0, i32* %18, align 4
  %24 = ptrtoint i8** %1 to i32
  store i32 %24, i32* %20, align 8
  %25 = ptrtoint i8** %2 to i32
  store i32 %25, i32* %22, align 4
  store i32 %0, i32* %13, align 4
  store i32 %14, i32* %11, align 4
  store i32 %14, i32* %9, align 8
  store i32 ptrtoint (i8* getelementptr inbounds ([26 x i8], [26 x i8]* @data_80482e0, i32 0, i32 22) to i32), i32* %7, align 4
  %26 = bitcast i32** %12 to i32*
  %27 = call i32 @sub_80483f0__Ai_Sii_B_0(i32 %14, i32* nonnull %26)
  %28 = load i32, i32* %16, align 8
  %29 = call %struct.Memory* @__remill_function_return(%struct.State* undef, i32 %28, %struct.Memory* null)
  ret i32 %27
}

; Function Attrs: noinline
define i32 @sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant(i32 %0, i8** %1, i8** %2) local_unnamed_addr #0 {
  %4 = call i8* @llvm.returnaddress(i32 0)
  %5 = alloca %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, align 8

  %additional_alloca_usage = ptrtoint %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5 to i64

  %6 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5, i32 0, i32 25
  %7 = bitcast i32** %6 to i32*
  %8 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5, i32 0, i32 26
  %9 = bitcast i32** %8 to i32*
  %10 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5, i32 0, i32 27
  %11 = bitcast i32** %10 to i32*
  %12 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5, i32 0, i32 31
  %13 = bitcast i32** %12 to i32*
  %14 = ptrtoint i32** %12 to i32
  %15 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5, i32 0, i32 32
  %16 = bitcast i32** %15 to i32*
  %17 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5, i32 0, i32 33
  %18 = bitcast i32** %17 to i32*
  %19 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5, i32 0, i32 34
  %20 = bitcast i32** %19 to i32*
  %21 = getelementptr inbounds %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type, %sub_80482e0__Ai_S_Sb_S_Sbi_B_0_variant.frame_type* %5, i32 0, i32 35
  %22 = bitcast i32** %21 to i32*
  %23 = ptrtoint i8* %4 to i32
  store i32 %23, i32* %16, align 8
  store i32 %0, i32* %18, align 4
  %24 = ptrtoint i8** %1 to i32
  store i32 %24, i32* %20, align 8
  %25 = ptrtoint i8** %2 to i32
  store i32 %25, i32* %22, align 4
  store i32 %0, i32* %13, align 4
  store i32 %14, i32* %11, align 4
  store i32 %14, i32* %9, align 8
  store i32 ptrtoint (i8* getelementptr inbounds ([26 x i8], [26 x i8]* @data_80482e0, i32 0, i32 22) to i32), i32* %7, align 4
  %26 = bitcast i32** %12 to i32*
  %27 = call i32 @sub_80483f0__Ai_Sii_B_0(i32 %14, i32* nonnull %26)
  %28 = load i32, i32* %16, align 8
  %29 = call %struct.Memory* @__remill_function_return(%struct.State* undef, i32 %28, %struct.Memory* null)
  ret i32 %27
}

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local %struct.Memory* @__remill_function_return(%struct.State* nonnull align 1, i32, %struct.Memory*) local_unnamed_addr #1

; Function Attrs: nounwind readnone
declare i8* @llvm.returnaddress(i32 immarg) #2

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { nounwind readnone }
