; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

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

@__anvill_reg_RBP = internal local_unnamed_addr global i64 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@__anvill_pc = internal global i8 0
@llvm.compiler.used = appending global [4 x i8*] [i8* bitcast (i64 (i64, i64, i32 ()*)* @sub_4003b4__All_Svl_B_0 to i8*), i8* bitcast (i64 (i32)* @target to i8*), i8* bitcast (i32 (i32, i8**, i8**)* @main to i8*), i8* bitcast (i32 (i32 (i32, i8**, i8**)*, i32, i8**, i32 (i32, i8**, i8**)*, i32 ()*, i32 ()*, i8*)* @__libc_start_main to i8*)], section "llvm.metadata"
@__anvill_stack_minus_32 = global i8 0
@__anvill_stack_minus_31 = global i8 0
@__anvill_stack_minus_30 = global i8 0
@__anvill_stack_minus_29 = global i8 0
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

; Function Attrs: noinline
declare i64 @sub_4003b4__All_Svl_B_0(i64, i64, i32 ()*) #0

; Function Attrs: noinline
define i32 @main(i32 %0, i8** %1, i8** %2) #0 {
  %4 = call i64 @target(i32 -559038737)
  %5 = trunc i64 %4 to i32
  ret i32 %5
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_64(%struct.Memory*, i64, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_32(%struct.Memory*, i64, i32) local_unnamed_addr #1

; Function Attrs: noinline
define i64 @target(i32 %0) #0 {
  %.sroa.10.4.extract.trunc = and i32 %0, 3
  switch i32 %.sroa.10.4.extract.trunc, label %18 [
    i32 0, label %2
    i32 1, label %10
    i32 2, label %26
  ]

2:                                                ; preds = %1
  %3 = or i32 %0, -1163210561
  %4 = xor i32 %0, 2
  %5 = mul i32 %4, %3
  %6 = and i32 %5, -16777216
  %7 = and i32 %5, 16711680
  %8 = and i32 %5, 65280
  %9 = and i32 %5, 255
  br label %34

10:                                               ; preds = %1
  %11 = and i32 %0, -1163210561
  %12 = add i32 %0, 3
  %13 = mul i32 %12, %11
  %14 = and i32 %13, -16777216
  %15 = and i32 %13, 16711680
  %16 = and i32 %13, 65280
  %17 = and i32 %13, 255
  br label %34

18:                                               ; preds = %1
  %19 = add i32 %0, -1163210561
  %20 = and i32 %0, 5
  %21 = mul i32 %20, %19
  %22 = and i32 %21, -16777216
  %23 = and i32 %21, 16711680
  %24 = and i32 %21, 65280
  %25 = and i32 %21, 255
  br label %34

26:                                               ; preds = %1
  %27 = xor i32 %0, -1163210561
  %28 = or i32 %0, 4
  %29 = mul i32 %28, %27
  %30 = and i32 %29, -16777216
  %31 = and i32 %29, 16711680
  %32 = and i32 %29, 65280
  %33 = and i32 %29, 255
  br label %34

34:                                               ; preds = %18, %26, %10, %2
  %35 = phi i32 [ %30, %26 ], [ %22, %18 ], [ %14, %10 ], [ %6, %2 ]
  %36 = phi i32 [ %31, %26 ], [ %23, %18 ], [ %15, %10 ], [ %7, %2 ]
  %37 = phi i32 [ %32, %26 ], [ %24, %18 ], [ %16, %10 ], [ %8, %2 ]
  %38 = phi i32 [ %33, %26 ], [ %25, %18 ], [ %17, %10 ], [ %9, %2 ]
  %.sroa.8.0.insert.insert = or i32 %35, %36
  %.sroa.7.0.insert.insert = or i32 %.sroa.8.0.insert.insert, %37
  %.sroa.0.0.insert.insert = or i32 %.sroa.7.0.insert.insert, %38
  %39 = zext i32 %.sroa.0.0.insert.insert to i64
  ret i64 %39
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(%struct.Memory*, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local %struct.Memory* @__remill_function_return(%struct.State* nonnull align 1, i64, %struct.Memory*) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i32 @__remill_read_memory_32(%struct.Memory*, i64) local_unnamed_addr #1

; Function Attrs: noinline
declare x86_64_sysvcc i32 @__libc_start_main(i32 (i32, i8**, i8**)*, i32, i8**, i32 (i32, i8**, i8**)*, i32 ()*, i32 ()*, i8*) #0

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
