; ModuleID = 'test_binja_var_none_type_rt.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

%sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0 = type <{ [48 x i8] }>

@var_400654_h = global i16 1
@var_400656_b = global i8 11
@__anvill_reg_RBP = internal local_unnamed_addr global i64 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@__anvill_pc = internal global i8 0
@llvm.compiler.used = appending global [7 x ptr] [ptr @sub_4003d4__All_Svl_B_0, ptr @xor_swap, ptr @atoi, ptr @main, ptr @__libc_start_main, ptr @var_400654_h, ptr @var_400656_b], section "llvm.metadata"
@__anvill_stack_minus_48 = global i8 0
@__anvill_stack_minus_47 = global i8 0
@__anvill_stack_minus_46 = global i8 0
@__anvill_stack_minus_45 = global i8 0
@__anvill_stack_minus_44 = global i8 0
@__anvill_stack_minus_43 = global i8 0
@__anvill_stack_minus_42 = global i8 0
@__anvill_stack_minus_41 = global i8 0
@__anvill_stack_minus_40 = global i8 0
@__anvill_stack_minus_39 = global i8 0
@__anvill_stack_minus_38 = global i8 0
@__anvill_stack_minus_37 = global i8 0
@__anvill_stack_minus_36 = global i8 0
@__anvill_stack_minus_35 = global i8 0
@__anvill_stack_minus_34 = global i8 0
@__anvill_stack_minus_33 = global i8 0
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
declare i64 @sub_4003d4__All_Svl_B_0(i64, i64, ptr) #0

; Function Attrs: noinline
define i32 @main(i32 %0, ptr %1, ptr %2) #0 {
  %4 = alloca %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, align 8
  %5 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 0
  %6 = load i8, ptr @__anvill_stack_minus_48, align 1
  store i8 %6, ptr %5, align 8
  %7 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 1
  %8 = load i8, ptr @__anvill_stack_minus_47, align 1
  store i8 %8, ptr %7, align 1
  %9 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 2
  %10 = load i8, ptr @__anvill_stack_minus_46, align 1
  store i8 %10, ptr %9, align 2
  %11 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 3
  %12 = load i8, ptr @__anvill_stack_minus_45, align 1
  store i8 %12, ptr %11, align 1
  %13 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 4
  %14 = load i8, ptr @__anvill_stack_minus_44, align 1
  store i8 %14, ptr %13, align 4
  %15 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 5
  %16 = load i8, ptr @__anvill_stack_minus_43, align 1
  store i8 %16, ptr %15, align 1
  %17 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 6
  %18 = load i8, ptr @__anvill_stack_minus_42, align 1
  store i8 %18, ptr %17, align 2
  %19 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 7
  %20 = load i8, ptr @__anvill_stack_minus_41, align 1
  store i8 %20, ptr %19, align 1
  %21 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 8
  %22 = load i8, ptr @__anvill_stack_minus_40, align 1
  store i8 %22, ptr %21, align 8
  %23 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 9
  %24 = load i8, ptr @__anvill_stack_minus_39, align 1
  store i8 %24, ptr %23, align 1
  %25 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 10
  %26 = load i8, ptr @__anvill_stack_minus_38, align 1
  store i8 %26, ptr %25, align 2
  %27 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 11
  %28 = load i8, ptr @__anvill_stack_minus_37, align 1
  store i8 %28, ptr %27, align 1
  %29 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 12
  %30 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 16
  %31 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 20
  %32 = load i8, ptr @__anvill_stack_minus_28, align 1
  store i8 %32, ptr %31, align 4
  %33 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 21
  %34 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 23
  %35 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 24
  %36 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 32
  %37 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 36
  %38 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, ptr %4, i64 0, i32 0, i64 40
  %39 = load i64, ptr @__anvill_reg_RBP, align 8
  %40 = ptrtoint ptr %1 to i64
  %41 = bitcast ptr %38 to ptr
  store i64 %39, ptr %41, align 8
  %42 = bitcast ptr %37 to ptr
  store i32 0, ptr %42, align 4
  %43 = bitcast ptr %36 to ptr
  store i32 %0, ptr %43, align 8
  %44 = bitcast ptr %35 to ptr
  store i64 %40, ptr %44, align 8
  %45 = load i16, ptr @var_400654_h, align 2
  %46 = bitcast ptr %33 to ptr
  store i16 %45, ptr %46, align 2
  %47 = load i8, ptr @var_400656_b, align 1
  store i8 %47, ptr %34, align 1
  %48 = bitcast ptr %30 to ptr
  store i32 3, ptr %48, align 8
  %49 = bitcast ptr %29 to ptr
  store i32 1, ptr %49, align 4
  br label %50

50:                                               ; preds = %86, %3
  %51 = phi i64 [ 4195674, %3 ], [ %105, %86 ]
  %52 = load i32, ptr %49, align 4
  %53 = load i32, ptr %43, align 8
  %54 = sub i32 %52, %53
  %55 = lshr i32 %54, 31
  %56 = lshr i32 %52, 31
  %57 = lshr i32 %53, 31
  %58 = xor i32 %57, %56
  %59 = xor i32 %55, %56
  %60 = add nuw nsw i32 %59, %58
  %61 = icmp eq i32 %60, 2
  store i8 0, ptr %27, align 1
  %62 = icmp sgt i32 %54, -1
  %63 = xor i1 %62, %61
  %64 = select i1 %63, i64 29, i64 17
  %65 = add i64 %51, %64
  br i1 %63, label %79, label %66

66:                                               ; preds = %50
  %67 = load i32, ptr %48, align 8
  %68 = sub i32 %52, %67
  %69 = lshr i32 %68, 31
  %70 = lshr i32 %67, 31
  %71 = xor i32 %70, %56
  %72 = xor i32 %69, %56
  %73 = add nuw nsw i32 %72, %71
  %74 = icmp eq i32 %73, 2
  %75 = icmp slt i32 %68, 0
  %76 = xor i1 %75, %74
  %77 = zext i1 %76 to i8
  %78 = add i64 %65, 12
  store i8 %77, ptr %27, align 1
  br label %79

79:                                               ; preds = %66, %50
  %80 = phi i64 [ %65, %50 ], [ %78, %66 ]
  %81 = load i8, ptr %27, align 1
  %82 = and i8 %81, 1
  %83 = icmp eq i8 %82, 0
  %84 = select i1 %83, i64 11, i64 16
  %85 = add i64 %80, %84
  br i1 %83, label %106, label %86

86:                                               ; preds = %79
  %87 = load i64, ptr %44, align 8
  %88 = sext i32 %52 to i64
  %89 = shl nsw i64 %88, 3
  %90 = add i64 %89, %87
  %91 = inttoptr i64 %90 to ptr
  %92 = load ptr, ptr %91, align 8
  %93 = add i64 %85, 17
  %94 = bitcast ptr %4 to ptr
  store i64 %93, ptr %94, align 8
  %95 = call i64 @atoi(ptr %92)
  %96 = load i32, ptr %49, align 4
  %97 = add i32 %96, -1
  %98 = sext i32 %97 to i64
  %99 = ptrtoint ptr %33 to i64
  %100 = add i64 %98, %99
  %101 = trunc i64 %95 to i8
  %102 = inttoptr i64 %100 to ptr
  store i8 %101, ptr %102, align 1
  %103 = load i32, ptr %49, align 4
  %104 = add i32 %103, 1
  store i32 %104, ptr %49, align 4
  %105 = add i64 %85, -45
  br label %50

106:                                              ; preds = %79
  %107 = add i64 %85, 58
  %108 = bitcast ptr %4 to ptr
  store i64 %107, ptr %108, align 8
  %109 = call ptr @xor_swap(ptr nonnull %33)
  %110 = load i8, ptr %33, align 1
  %111 = zext i8 %110 to i32
  ret i32 %111
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_64(ptr, i64, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_32(ptr, i64, i32) local_unnamed_addr #1

; Function Attrs: readnone
declare ptr @__anvill_type_hint_S_Sb(i64) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local zeroext i16 @__remill_read_memory_16(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_16(ptr, i64, i16 zeroext) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local zeroext i8 @__remill_read_memory_8(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_8(ptr, i64, i8 zeroext) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i32 @__remill_read_memory_32(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(ptr, i64) local_unnamed_addr #1

; Function Attrs: readnone
declare ptr @__anvill_type_hint_Sb(i64) local_unnamed_addr #2

; Function Attrs: noinline
define i64 @atoi(ptr %0) #0 {
  %2 = load i8, ptr %0, align 1
  %3 = add i8 %2, -48
  %4 = zext i8 %3 to i64
  ret i64 %4
}

; Function Attrs: readnone
declare ptr @__anvill_type_hint_Sh(i64) local_unnamed_addr #2

; Function Attrs: noinline
define ptr @xor_swap(ptr %0) #0 {
  %2 = ptrtoint ptr %0 to i64
  %3 = load i8, ptr %0, align 1
  %4 = add i64 %2, 1
  %5 = inttoptr i64 %4 to ptr
  %6 = load i8, ptr %5, align 1
  %7 = xor i8 %6, %3
  store i8 %7, ptr %0, align 1
  %8 = load i8, ptr %5, align 1
  %9 = xor i8 %8, %7
  store i8 %9, ptr %5, align 1
  %10 = load i8, ptr %0, align 1
  %11 = xor i8 %9, %10
  store i8 %11, ptr %0, align 1
  ret ptr %0
}

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local ptr @__remill_function_return(ptr nonnull align 1, i64, ptr) local_unnamed_addr #3

; Function Attrs: noinline
declare x86_64_sysvcc i32 @__libc_start_main(ptr, i32, ptr, ptr, ptr, ptr, ptr) #0

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { readnone }
attributes #3 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
