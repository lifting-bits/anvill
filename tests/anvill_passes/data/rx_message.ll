; ModuleID = 'rx_message.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

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
@llvm.compiler.used = appending global [10 x ptr] [ptr @putchar, ptr @printf, ptr @brake_on, ptr @brake_off, ptr @rx_message_routine, ptr getelementptr inbounds ([1 x i8], ptr @var_4007c1__Cbx1_D, i32 0, i32 0), ptr getelementptr inbounds ([1 x i8], ptr @var_4007ce__Cbx1_D, i32 0, i32 0), ptr @brake_state, ptr @need_to_flash, ptr @previous_brake_state], section "llvm.metadata"
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
declare i32 @printf(ptr, ...) #0

; Function Attrs: noinline
define i64 @rx_message_routine(ptr %0) #0 {
  %2 = ptrtoint ptr %0 to i64
  %3 = add i64 %2, 4
  %4 = inttoptr i64 %3 to ptr
  %5 = load i8, ptr %4, align 1
  %6 = call i32 (ptr, ...) @printf(ptr nonnull getelementptr inbounds ([1 x i8], ptr @var_4007c1__Cbx1_D, i32 0, i32 0))
  %7 = call i32 (ptr, ...) @printf(ptr nonnull getelementptr inbounds ([1 x i8], ptr @var_4007ce__Cbx1_D, i32 0, i32 0))
  %8 = call i32 (ptr, ...) @printf(ptr nonnull getelementptr inbounds ([1 x i8], ptr @var_4007c1__Cbx1_D, i32 0, i32 0))
  %9 = call i32 (ptr, ...) @printf(ptr nonnull getelementptr inbounds ([1 x i8], ptr @var_4007ce__Cbx1_D, i32 0, i32 0))
  %10 = call i32 @putchar(i32 93)
  %11 = call i32 @putchar(i32 10)
  %12 = and i8 %5, 12
  %13 = icmp eq i8 %12, 0
  br i1 %13, label %14, label %17

14:                                               ; preds = %1
  store i8 0, ptr @brake_state, align 1
  store i8 0, ptr @need_to_flash, align 1
  %15 = call i64 @brake_off()
  %16 = and i64 %15, -256
  br label %33

17:                                               ; preds = %1
  %18 = add i64 %2, 2
  %19 = inttoptr i64 %18 to ptr
  %20 = load i16, ptr %19, align 2
  store i8 1, ptr @brake_state, align 1
  %21 = call i64 @brake_on()
  %22 = icmp slt i16 %20, 1
  %23 = and i64 %21, -256
  br i1 %22, label %33, label %24

24:                                               ; preds = %17
  %25 = load i8, ptr @previous_brake_state, align 1
  %26 = load i8, ptr @brake_state, align 1
  %27 = icmp eq i8 %25, %26
  br i1 %27, label %33, label %28

28:                                               ; preds = %24
  store i8 1, ptr @need_to_flash, align 1
  %29 = call i32 (ptr, ...) @printf(ptr nonnull getelementptr inbounds ([1 x i8], ptr @var_4007c1__Cbx1_D, i32 0, i32 0))
  %30 = call i32 @putchar(i32 10)
  %31 = and i32 %30, -256
  %32 = zext i32 %31 to i64
  br label %33

33:                                               ; preds = %28, %24, %17, %14
  %34 = phi i64 [ %16, %14 ], [ %23, %17 ], [ %23, %24 ], [ %32, %28 ]
  %35 = load i8, ptr @brake_state, align 1
  %36 = zext i8 %35 to i64
  %37 = or i64 %34, %36
  store i8 %35, ptr @previous_brake_state, align 1
  ret i64 %37
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare ptr @__remill_write_memory_64(ptr, i64, i64) local_unnamed_addr #1

; Function Attrs: readnone
declare ptr @__anvill_type_hint_Sb(i64) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare zeroext i8 @__remill_read_memory_8(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare ptr @__remill_write_memory_8(ptr, i64, i8 zeroext) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare zeroext i16 @__remill_read_memory_16(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare i64 @__remill_read_memory_64(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_function_return(ptr nonnull align 1, i64, ptr) local_unnamed_addr #3

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { readnone }
attributes #3 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
