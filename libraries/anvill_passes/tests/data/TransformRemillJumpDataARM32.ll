; ModuleID = 'test_arm32.o.bc'
source_filename = "lifted_code"
target datalayout = "e-m:e-p:32:32-Fi8-i64:64-v128:64:128-a:0:32-n32-S64"
target triple = "arm-pc-linux-gnu-elf"

%sub_0__Aiii_B_0.frame_type_part0 = type <{ [4 x i8] }>
%sub_0__Aiii_B_0.frame_type_part2 = type <{ [4 x i8] }>
%struct.State = type { %struct.ArchState, %struct.GPR, %struct.SR, i64 }
%struct.ArchState = type { i32, i32, %union.anon }
%union.anon = type { i64 }
%struct.GPR = type { i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg }
%struct.Reg = type { i32 }
%struct.SR = type { i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, [4 x i8] }
%struct.Memory = type opaque

@__anvill_reg_R2 = internal local_unnamed_addr global i32 0
@__anvill_reg_R3 = internal local_unnamed_addr global i32 0
@__anvill_reg_R4 = internal local_unnamed_addr global i32 0
@__anvill_reg_R5 = internal local_unnamed_addr global i32 0
@__anvill_reg_R6 = internal local_unnamed_addr global i32 0
@__anvill_reg_R7 = internal local_unnamed_addr global i32 0
@__anvill_reg_R8 = internal local_unnamed_addr global i32 0
@__anvill_reg_R9 = internal local_unnamed_addr global i32 0
@__anvill_reg_R10 = internal local_unnamed_addr global i32 0
@__anvill_reg_R11 = internal local_unnamed_addr global i32 0
@__anvill_reg_R12 = internal local_unnamed_addr global i32 0
@__anvill_reg_C = internal local_unnamed_addr global i8 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@__anvill_pc = internal global i8 0
@llvm.compiler.used = appending global [1 x i8*] [i8* bitcast (i32 (i32, i32)* @sub_0__Aiii_B_0 to i8*)], section "llvm.metadata"
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

; Function Attrs: noinline
define i32 @sub_0__Aiii_B_0(i32 %0, i32 %1) #0 {
  %3 = alloca i32, align 4
  %tmpcast = bitcast i32* %3 to %sub_0__Aiii_B_0.frame_type_part0*
  %4 = alloca %sub_0__Aiii_B_0.frame_type_part2, align 4
  %5 = bitcast i32* %3 to i8*
  %6 = load i8, i8* @__anvill_stack_minus_8, align 1
  store i8 %6, i8* %5, align 4
  %7 = getelementptr inbounds %sub_0__Aiii_B_0.frame_type_part0, %sub_0__Aiii_B_0.frame_type_part0* %tmpcast, i32 0, i32 0, i32 1
  %8 = load i8, i8* @__anvill_stack_minus_7, align 1
  store i8 %8, i8* %7, align 1
  %9 = getelementptr inbounds %sub_0__Aiii_B_0.frame_type_part0, %sub_0__Aiii_B_0.frame_type_part0* %tmpcast, i32 0, i32 0, i32 2
  %10 = load i8, i8* @__anvill_stack_minus_6, align 1
  store i8 %10, i8* %9, align 2
  %11 = getelementptr inbounds %sub_0__Aiii_B_0.frame_type_part0, %sub_0__Aiii_B_0.frame_type_part0* %tmpcast, i32 0, i32 0, i32 3
  %12 = load i8, i8* @__anvill_stack_minus_5, align 1
  store i8 %12, i8* %11, align 1
  %13 = getelementptr inbounds %sub_0__Aiii_B_0.frame_type_part2, %sub_0__Aiii_B_0.frame_type_part2* %4, i32 0, i32 0, i32 0
  %14 = load i8, i8* @__anvill_stack_0, align 1
  store i8 %14, i8* %13, align 4
  %15 = getelementptr inbounds %sub_0__Aiii_B_0.frame_type_part2, %sub_0__Aiii_B_0.frame_type_part2* %4, i32 0, i32 0, i32 1
  %16 = load i8, i8* @__anvill_stack_plus_1, align 1
  store i8 %16, i8* %15, align 1
  %17 = getelementptr inbounds %sub_0__Aiii_B_0.frame_type_part2, %sub_0__Aiii_B_0.frame_type_part2* %4, i32 0, i32 0, i32 2
  %18 = load i8, i8* @__anvill_stack_plus_2, align 1
  store i8 %18, i8* %17, align 2
  %19 = getelementptr inbounds %sub_0__Aiii_B_0.frame_type_part2, %sub_0__Aiii_B_0.frame_type_part2* %4, i32 0, i32 0, i32 3
  %20 = load i8, i8* @__anvill_stack_plus_3, align 1
  store i8 %20, i8* %19, align 1
  %21 = alloca %struct.State, align 8
  %22 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 0, i32 0
  store i32 0, i32* %22, align 8
  %23 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 0, i32 1
  store i32 0, i32* %23, align 4
  %24 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 0, i32 2, i32 0
  store i64 0, i64* %24, align 8
  %25 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 0
  store i32 0, i32* %25, align 8
  %26 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 1, i32 0
  store i32 0, i32* %26, align 4
  %27 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 2
  store i32 0, i32* %27, align 8
  %28 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 3, i32 0
  store i32 0, i32* %28, align 4
  %29 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 4
  store i32 0, i32* %29, align 8
  %30 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 5, i32 0
  %31 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 6
  store i32 0, i32* %31, align 8
  %32 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 7, i32 0
  %33 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 8
  store i32 0, i32* %33, align 8
  %34 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 9, i32 0
  %35 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 10
  store i32 0, i32* %35, align 8
  %36 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 11, i32 0
  %37 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 12
  store i32 0, i32* %37, align 8
  %38 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 13, i32 0
  %39 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 14
  store i32 0, i32* %39, align 8
  %40 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 15, i32 0
  %41 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 16
  store i32 0, i32* %41, align 8
  %42 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 17, i32 0
  %43 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 18
  store i32 0, i32* %43, align 8
  %44 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 19, i32 0
  %45 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 20
  store i32 0, i32* %45, align 8
  %46 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 21, i32 0
  %47 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 22
  store i32 0, i32* %47, align 8
  %48 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 23, i32 0
  %49 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 24
  store i32 0, i32* %49, align 8
  %50 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 25, i32 0
  %51 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 26
  store i32 0, i32* %51, align 8
  %52 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 27, i32 0
  %53 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 28
  store i32 0, i32* %53, align 8
  %54 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 29, i32 0
  %55 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 30
  store i32 0, i32* %55, align 8
  %56 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 1, i32 31, i32 0
  %57 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 0
  store i8 0, i8* %57, align 8
  %58 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 1
  %59 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 2
  store i8 0, i8* %59, align 2
  %60 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 3
  %61 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 4
  store i8 0, i8* %61, align 4
  %62 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 5
  %63 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 6
  store i8 0, i8* %63, align 2
  %64 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 7
  %65 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 8
  store i8 0, i8* %65, align 8
  %66 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 9
  store i8 0, i8* %66, align 1
  %67 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 10
  store i8 0, i8* %67, align 2
  %68 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 11
  store i8 0, i8* %68, align 1
  %69 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 12
  store i8 0, i8* %69, align 4
  %70 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 13
  store i8 0, i8* %70, align 1
  %71 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 14
  store i8 0, i8* %71, align 2
  %72 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 15
  store i8 0, i8* %72, align 1
  %73 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 16
  store i8 0, i8* %73, align 8
  %74 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 17
  store i8 0, i8* %74, align 1
  %75 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 18
  store i8 0, i8* %75, align 2
  %76 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 19
  store i8 0, i8* %76, align 1
  %77 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 20, i32 0
  store i8 0, i8* %77, align 4
  %78 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 20, i32 1
  store i8 0, i8* %78, align 1
  %79 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 20, i32 2
  store i8 0, i8* %79, align 2
  %80 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 2, i32 20, i32 3
  store i8 0, i8* %80, align 1
  %81 = getelementptr inbounds %struct.State, %struct.State* %21, i32 0, i32 3
  store i64 0, i64* %81, align 8
  %82 = load i32, i32* @__anvill_reg_R2, align 4
  store i32 %82, i32* %30, align 4
  %83 = load i32, i32* @__anvill_reg_R3, align 4
  store i32 %83, i32* %32, align 4
  %84 = load i32, i32* @__anvill_reg_R4, align 4
  store i32 %84, i32* %34, align 4
  %85 = load i32, i32* @__anvill_reg_R5, align 4
  store i32 %85, i32* %36, align 4
  %86 = load i32, i32* @__anvill_reg_R6, align 4
  store i32 %86, i32* %38, align 4
  %87 = load i32, i32* @__anvill_reg_R7, align 4
  store i32 %87, i32* %40, align 4
  %88 = load i32, i32* @__anvill_reg_R8, align 4
  store i32 %88, i32* %42, align 4
  %89 = load i32, i32* @__anvill_reg_R9, align 4
  store i32 %89, i32* %44, align 4
  %90 = load i32, i32* @__anvill_reg_R10, align 4
  store i32 %90, i32* %46, align 4
  %91 = load i32, i32* @__anvill_reg_R11, align 4
  store i32 %91, i32* %48, align 4
  %92 = load i32, i32* @__anvill_reg_R12, align 4
  store i32 %92, i32* %50, align 4
  store i32 ptrtoint (i8* @__anvill_ra to i32), i32* %54, align 4
  store i32 %0, i32* %26, align 4
  store i32 %1, i32* %28, align 4
  %93 = ptrtoint i32* %3 to i32
  store i32 %93, i32* %52, align 4
  %94 = sext i32 %1 to i64
  %95 = add nsw i64 %94, -1
  %96 = add i32 %1, -1
  %97 = lshr i32 %96, 31
  %98 = trunc i32 %97 to i8
  store i8 %98, i8* %58, align 1
  %99 = icmp eq i32 %96, 0
  %100 = zext i1 %99 to i8
  store i8 %100, i8* %60, align 1
  %101 = icmp ne i32 %1, 0
  %102 = zext i1 %101 to i8
  store i8 %102, i8* %62, align 1
  %103 = sext i32 %96 to i64
  %104 = icmp ne i64 %95, %103
  %105 = zext i1 %104 to i8
  store i8 %105, i8* %64, align 1
  store i32 8, i32* %56, align 4
  br i1 %99, label %106, label %107

106:                                              ; preds = %2
  store i32 %1, i32* %26, align 4
  br label %107

107:                                              ; preds = %106, %2
  store i32 0, i32* %26, align 4
  store i32 %82, i32* %3, align 4
  store i32 %82, i32* %30, align 4
  %108 = ptrtoint %sub_0__Aiii_B_0.frame_type_part2* %4 to i32
  store i32 %108, i32* %52, align 4
  store i32 or (i32 or (i32 or (i32 shl (i32 zext (i8 trunc (i32 lshr (i32 ptrtoint (i8* @__anvill_ra to i32), i32 24) to i8) to i32), i32 24), i32 shl (i32 zext (i8 trunc (i32 lshr (i32 ptrtoint (i8* @__anvill_ra to i32), i32 16) to i8) to i32), i32 16)), i32 shl (i32 zext (i8 trunc (i32 lshr (i32 ptrtoint (i8* @__anvill_ra to i32), i32 8) to i8) to i32), i32 8)), i32 zext (i8 ptrtoint (i8* @__anvill_ra to i8) to i32)), i32* %56, align 4
  %109 = call %struct.Memory* @__remill_jump(%struct.State* %21, i32 or (i32 or (i32 or (i32 shl (i32 zext (i8 trunc (i32 lshr (i32 ptrtoint (i8* @__anvill_ra to i32), i32 24) to i8) to i32), i32 24), i32 shl (i32 zext (i8 trunc (i32 lshr (i32 ptrtoint (i8* @__anvill_ra to i32), i32 16) to i8) to i32), i32 16)), i32 shl (i32 zext (i8 trunc (i32 lshr (i32 ptrtoint (i8* @__anvill_ra to i32), i32 8) to i8) to i32), i32 8)), i32 zext (i8 ptrtoint (i8* @__anvill_ra to i8) to i32)), %struct.Memory* null)
  %110 = load i32, i32* %26, align 4
  ret i32 %110
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare %struct.Memory* @__remill_write_memory_32(%struct.Memory*, i32, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare i32 @__remill_read_memory_32(%struct.Memory*, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare %struct.Memory* @__remill_jump(%struct.State* nonnull align 1, i32, %struct.Memory*) local_unnamed_addr #2

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
