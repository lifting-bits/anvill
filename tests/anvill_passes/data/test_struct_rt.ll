; ModuleID = 'test_struct_rt.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

@var_601028_l = global i64 180388626432
@var_60102c_l = global i64 42
@__anvill_reg_RBP = internal local_unnamed_addr global i64 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@llvm.compiler.used = appending global [7 x ptr] [ptr @sub_4003b4__All_Svl_B_0, ptr @main, ptr @__libc_start_main, ptr @var_601028_l, ptr @var_60102c_l, ptr @data_601028_i, ptr @data_60102c_i], section "llvm.metadata"
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

@data_601028_i = alias i32, ptr @var_601028_l
@data_60102c_i = alias i32, ptr @var_60102c_l

; Function Attrs: noinline
declare i64 @sub_4003b4__All_Svl_B_0(i64, i64, ptr) #0

; Function Attrs: noinline
define i32 @main(i32 %0, ptr %1, ptr %2) #0 {
  %4 = load i32, ptr @var_601028_l, align 8
  %5 = icmp eq i32 %4, 0
  br i1 %5, label %6, label %12

6:                                                ; preds = %3
  %7 = load i32, ptr @var_60102c_l, align 8
  %8 = and i32 %7, -16777216
  %9 = and i32 %7, 16711680
  %10 = and i32 %7, 65280
  %11 = and i32 %7, 255
  br label %17

12:                                               ; preds = %3
  %13 = and i32 %4, -16777216
  %14 = and i32 %4, 16711680
  %15 = and i32 %4, 65280
  %16 = and i32 %4, 255
  br label %17

17:                                               ; preds = %12, %6
  %18 = phi i32 [ %8, %6 ], [ %13, %12 ]
  %19 = phi i32 [ %9, %6 ], [ %14, %12 ]
  %20 = phi i32 [ %10, %6 ], [ %15, %12 ]
  %21 = phi i32 [ %11, %6 ], [ %16, %12 ]
  %.sroa.6.0.insert.insert = or i32 %18, %19
  %.sroa.5.0.insert.insert = or i32 %.sroa.6.0.insert.insert, %20
  %.sroa.0.0.insert.insert = or i32 %.sroa.5.0.insert.insert, %21
  ret i32 %.sroa.0.0.insert.insert
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_64(ptr, i64, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_32(ptr, i64, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i32 @__remill_read_memory_32(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local ptr @__remill_function_return(ptr nonnull align 1, i64, ptr) local_unnamed_addr #2

; Function Attrs: noinline
declare x86_64_sysvcc i32 @__libc_start_main(ptr, i32, ptr, ptr, ptr, ptr, ptr) #0

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
