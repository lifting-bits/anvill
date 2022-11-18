; ModuleID = 'TestingUnresolvedEntity.ll'
source_filename = "slice"

@__anvill_stack_plus_24 = external global i32
@__anvill_stack_plus_20 = external global i32
@__anvill_stack_plus_16 = external global i32
@__anvill_stack_plus_12 = external global i32
@__anvill_stack_plus_8 = external global i32
@__anvill_stack_plus_4 = external global i32
@__anvill_pc = external global i32

; Function Attrs: noinline
define i32 @sub_12b30__A_SBI_B_0.6(ptr %0) #0 {
  %2 = load i32, ptr @__anvill_stack_plus_24, align 4
  %3 = load i32, ptr @__anvill_stack_plus_20, align 4
  %4 = load i32, ptr @__anvill_stack_plus_16, align 4
  %5 = load i32, ptr @__anvill_stack_plus_12, align 4
  %6 = load i32, ptr @__anvill_stack_plus_8, align 4
  %7 = load i32, ptr @__anvill_stack_plus_4, align 4
  %8 = ptrtoint ptr %0 to i32
  %9 = call i32 @sub_54__AvI_B_0()
  %10 = add i32 %8, 8
  %11 = inttoptr i32 %10 to ptr
  %12 = load i32, ptr %11, align 4
  %13 = add i32 %8, 12
  %14 = inttoptr i32 %13 to ptr
  %15 = load i32, ptr %14, align 4
  %16 = xor i32 %12, -1
  %17 = zext i32 %2 to i64
  %18 = zext i32 %16 to i64
  %19 = add nuw nsw i64 %18, %17
  %20 = trunc i64 %19 to i32
  %21 = add i32 %20, 1
  %22 = icmp ugt i64 %19, 4294967294
  %23 = xor i32 %15, -1
  %24 = add i32 %3, %23
  %25 = zext i1 %22 to i32
  %26 = add i32 %24, %25
  %27 = call i32 @sub_fffffff0__AIIIII_B_0(i32 %21, i32 %26, i32 %2, i32 %3)
  %28 = load i32, ptr @sub_60__AII_B_0, align 4
  %29 = call i32 @sub_10__AIIIII_B_0(i32 %27, i32 %26, i32 0, i32 %28)
  %30 = call i32 @sub_38__A_SBI_SBI_B_0(i32 %29, i32 %26, i32 0, i32 1071644672)
  %31 = icmp eq i32 %30, 0
  br i1 %31, label %sub_12b30__A_SBI_B_0.lifted.exit, label %inst_12b84_not_taken_12b88.i

inst_12b84_not_taken_12b88.i:                     ; preds = %1
  %32 = add i32 %8, 31
  %33 = inttoptr i32 %32 to ptr
  %34 = load i8, ptr %33, align 1
  %35 = zext i8 %34 to i32
  %36 = add nsw i32 %35, -1
  %37 = icmp ne i8 %34, 15
  %38 = icmp ugt i32 %36, 13
  %39 = and i1 %37, %38
  br i1 %39, label %inst_12c44.i, label %inst_12b94_not_taken_12b98.i

inst_12b94_not_taken_12b98.i:                     ; preds = %inst_12b84_not_taken_12b88.i
  %40 = shl nsw i32 %36, 2
  %41 = add i32 %40, add (i32 ptrtoint (ptr @__anvill_pc to i32), i32 76696)
  %42 = inttoptr i32 %41 to ptr
  %43 = load i32, ptr %42, align 4
  %44 = call i32 (i32, ...) @__anvill_complete_switch(i32 %43, i32 76764, i32 76796, i32 76824, i32 76840, i32 76868)
  br label %inst_12c44.i

inst_12c44.i:                                     ; preds = %inst_12b94_not_taken_12b98.i, %inst_12b84_not_taken_12b88.i
  %45 = call i32 @sub_54__AvI_B_0()
  %46 = inttoptr i32 %10 to ptr
  store i32 %2, ptr %46, align 4
  %47 = inttoptr i32 %13 to ptr
  store i32 %3, ptr %47, align 4
  br label %sub_12b30__A_SBI_B_0.lifted.exit

sub_12b30__A_SBI_B_0.lifted.exit:                 ; preds = %inst_12c44.i, %1
  %48 = phi i32 [ %30, %1 ], [ %2, %inst_12c44.i ]
  %49 = call ptr @__remill_function_return(ptr undef, i32 %7, ptr undef)
  ret i32 %48
}

; Function Attrs: noinline
declare i32 @sub_54__AvI_B_0() #0

; Function Attrs: noinline
declare i32 @sub_fffffff0__AIIIII_B_0(i32, i32, i32, i32) #0

; Function Attrs: noinline
declare i32 @sub_60__AII_B_0(i32) #0

; Function Attrs: noinline
declare i32 @sub_10__AIIIII_B_0(i32, i32, i32, i32) #0

; Function Attrs: noinline
declare i32 @sub_38__A_SBI_SBI_B_0(ptr, i32, ptr) #0

; Function Attrs: readnone
declare i32 @__anvill_complete_switch(i32, ...) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_function_return(ptr nonnull align 1, i32, ptr) local_unnamed_addr #2

attributes #0 = { noinline }
attributes #1 = { readnone }
attributes #2 = { noduplicate noinline nounwind optnone "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
