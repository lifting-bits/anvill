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
@var_4007c1__Cbx1_D = external global [1 x i8]
@var_4007ce__Cbx1_D = external global [1 x i8]
@brake_state = external global i8
@need_to_flash = external global i8
@previous_brake_state = external global i8
@__anvill_reg_RAX = internal local_unnamed_addr global i64 0
@__anvill_reg_RBX = internal local_unnamed_addr global i64 0
@__anvill_reg_R14 = internal local_unnamed_addr global i64 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@__anvill_pc = internal global i8 0
@llvm.compiler.used = appending global [10 x i8*] [i8* bitcast (i32 (i32)* @putchar to i8*), i8* bitcast (i32 (i8*, ...)* @printf to i8*), i8* bitcast (i64 ()* @brake_on to i8*), i8* bitcast (i64 ()* @brake_off to i8*), i8* bitcast (i64 (i8*)* @rx_message_routine to i8*), i8* getelementptr inbounds ([1 x i8], [1 x i8]* @var_4007c1__Cbx1_D, i32 0, i32 0), i8* getelementptr inbounds ([1 x i8], [1 x i8]* @var_4007ce__Cbx1_D, i32 0, i32 0), i8* @brake_state, i8* @need_to_flash, i8* @previous_brake_state], section "llvm.metadata"
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
declare i32 @putchar(i32) #0
; Function Attrs: noinline
declare i64 @brake_off() #0
; Function Attrs: noinline
declare i64 @brake_on() #0
; Function Attrs: noinline
declare i32 @printf(i8*, ...) #0
; Function Attrs: noinline
define i64 @rx_message_routine(i8* %0) #0 {
  %2 = ptrtoint i8* %0 to i64
  %3 = add i64 %2, 4
  %4 = inttoptr i64 %3 to i8*
  %5 = load i8, i8* %4, align 1
  %6 = call i32 (i8*, ...) @printf(i8* nonnull getelementptr inbounds ([1 x i8], [1 x i8]* @var_4007c1__Cbx1_D, i32 0, i32 0))
  %7 = call i32 (i8*, ...) @printf(i8* nonnull getelementptr inbounds ([1 x i8], [1 x i8]* @var_4007ce__Cbx1_D, i32 0, i32 0))
  %8 = call i32 (i8*, ...) @printf(i8* nonnull getelementptr inbounds ([1 x i8], [1 x i8]* @var_4007c1__Cbx1_D, i32 0, i32 0))
  %9 = call i32 (i8*, ...) @printf(i8* nonnull getelementptr inbounds ([1 x i8], [1 x i8]* @var_4007ce__Cbx1_D, i32 0, i32 0))
  %10 = call i32 @putchar(i32 93)
  %11 = call i32 @putchar(i32 10)
  %12 = and i8 %5, 12
  %13 = icmp eq i8 %12, 0
  br i1 %13, label %14, label %17
14:                                               ; preds = %1
  store i8 0, i8* @brake_state, align 1
  store i8 0, i8* @need_to_flash, align 1
  %15 = call i64 @brake_off()
  %16 = and i64 %15, -256
  br label %33
17:                                               ; preds = %1
  %18 = add i64 %2, 2
  %19 = inttoptr i64 %18 to i16*
  %20 = load i16, i16* %19, align 2
  store i8 1, i8* @brake_state, align 1
  %21 = call i64 @brake_on()
  %22 = icmp slt i16 %20, 1
  %23 = and i64 %21, -256
  br i1 %22, label %33, label %24
24:                                               ; preds = %17
  %25 = load i8, i8* @previous_brake_state, align 1
  %26 = load i8, i8* @brake_state, align 1
  %27 = icmp eq i8 %25, %26
  br i1 %27, label %33, label %28
28:                                               ; preds = %24
  store i8 1, i8* @need_to_flash, align 1
  %29 = call i32 (i8*, ...) @printf(i8* nonnull getelementptr inbounds ([1 x i8], [1 x i8]* @var_4007c1__Cbx1_D, i32 0, i32 0))
  %30 = call i32 @putchar(i32 10)
  %31 = and i32 %30, -256
  %32 = zext i32 %31 to i64
  br label %33
33:                                               ; preds = %28, %24, %17, %14
  %34 = phi i64 [ %16, %14 ], [ %23, %17 ], [ %23, %24 ], [ %32, %28 ]
  %35 = load i8, i8* @brake_state, align 1
  %36 = zext i8 %35 to i64
  %37 = or i64 %34, %36
  store i8 %35, i8* @previous_brake_state, align 1
  ret i64 %37
}
; Function Attrs: noduplicate noinline nounwind optnone readnone
declare %struct.Memory* @__remill_write_memory_64(%struct.Memory*, i64, i64) local_unnamed_addr #1
; Function Attrs: readnone
declare i8* @__anvill_type_hint_Sb(i64) local_unnamed_addr #2
; Function Attrs: noduplicate noinline nounwind optnone readnone
declare zeroext i8 @__remill_read_memory_8(%struct.Memory*, i64) local_unnamed_addr #1
; Function Attrs: noduplicate noinline nounwind optnone readnone
declare %struct.Memory* @__remill_write_memory_8(%struct.Memory*, i64, i8 zeroext) local_unnamed_addr #1
; Function Attrs: noduplicate noinline nounwind optnone readnone
declare zeroext i16 @__remill_read_memory_16(%struct.Memory*, i64) local_unnamed_addr #1
; Function Attrs: noduplicate noinline nounwind optnone readnone
declare i64 @__remill_read_memory_64(%struct.Memory*, i64) local_unnamed_addr #1
; Function Attrs: noduplicate noinline nounwind optnone
declare %struct.Memory* @__remill_function_return(%struct.State* nonnull align 1, i64, %struct.Memory*) local_unnamed_addr #3
attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { readnone }
attributes #3 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
