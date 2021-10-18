; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:o-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx-macho"

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
%struct.Reg = type { %union.anon }
%struct.GPR = type { i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg }
%struct.X87Stack = type { [8 x %struct.anon.3] }
%struct.anon.3 = type { [6 x i8], %struct.float80_t }
%struct.float80_t = type { [10 x i8] }
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
%union.vec128_t = type { %struct.uint128v1_t }
%struct.uint128v1_t = type { [1 x i128] }
%struct.SegmentCaches = type { %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow }
%struct.SegmentShadow = type { %union.anon, i32, i32 }

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_zero_flag_computation(i1 zeroext, ...) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_sign_flag_computation(i1 zeroext, ...) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_overflow_flag_computation(i1 zeroext, ...) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare i64 @__remill_read_memory_64(%struct.Memory*, i64) local_unnamed_addr #0

; Function Attrs: noduplicate noinline nounwind optnone
declare %struct.Memory* @__remill_function_return(%struct.State* nonnull align 1, i64, %struct.Memory*) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare %struct.Memory* @__remill_missing_block(%struct.State* nonnull align 1, i64, %struct.Memory*) local_unnamed_addr #1

; Function Attrs: nounwind ssp
define %struct.Memory* @slice(%struct.Memory* %0, i64 %RAX, i64 %RDX, i64* nocapture %RIP_output) local_unnamed_addr #2 {
  %2 = add i64 %RDX, %RAX
  %3 = icmp eq i64 %2, 0
  %4 = tail call zeroext i1 (i1, ...) @__remill_zero_flag_computation(i1 zeroext %3, i64 %2) #3
  %5 = icmp slt i64 %2, 0
  %6 = tail call zeroext i1 (i1, ...) @__remill_sign_flag_computation(i1 zeroext %5, i64 %2) #3
  %7 = lshr i64 %RAX, 63
  %8 = lshr i64 %RDX, 63
  %9 = lshr i64 %2, 63
  %10 = xor i64 %9, %7
  %11 = xor i64 %9, %8
  %12 = add nuw nsw i64 %10, %11
  %13 = icmp eq i64 %12, 2
  %14 = tail call zeroext i1 (i1, ...) @__remill_overflow_flag_computation(i1 zeroext %13, i64 %RAX, i64 %RDX, i64 %2) #3
  %15 = xor i1 %6, %14
  %16 = or i1 %4, %15
  br i1 %16, label %17, label %20

17:                                               ; preds = %1
  %18 = tail call i64 @__remill_read_memory_64(%struct.Memory* %0, i64 undef) #3
  %19 = tail call %struct.Memory* @__remill_function_return(%struct.State* undef, i64 %18, %struct.Memory* %0) #4, !noalias !0
  br label %sub_0.exit

20:                                               ; preds = %1
  %21 = tail call %struct.Memory* @__remill_missing_block(%struct.State* undef, i64 8, %struct.Memory* %0) #4, !noalias !0
  br label %sub_0.exit

sub_0.exit:                                       ; preds = %20, %17
  %.sroa.13.0 = phi i64 [ %18, %17 ], [ 8, %20 ]
  %22 = phi %struct.Memory* [ %19, %17 ], [ %21, %20 ]
  store i64 %.sroa.13.0, i64* %RIP_output, align 8
  ret %struct.Memory* %22
}

attributes #0 = { noduplicate noinline nounwind optnone readnone willreturn "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { noduplicate noinline nounwind optnone "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { nounwind ssp }
attributes #3 = { nobuiltin nounwind readnone willreturn "no-builtins" }
attributes #4 = { nounwind }

!0 = !{!1}
!1 = distinct !{!1, !2, !"sub_0: %state"}
!2 = distinct !{!2, !"sub_0"}
