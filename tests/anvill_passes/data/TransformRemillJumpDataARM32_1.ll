; ModuleID = 'TransformRemillJumpDataARM32_1.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-p:32:32-Fi8-i64:64-v128:64:128-a:0:32-n32-S64"
target triple = "arm-pc-linux-gnu-elf"

%sub_0__Avi_B_0.frame_type_part0 = type <{ [4 x i8] }>
%struct.State = type { %struct.ArchState, %struct.GPR, %struct.SR, i64 }
%struct.ArchState = type { i32, i32, %union.anon }
%union.anon = type { i64 }
%struct.GPR = type { i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg, i32, %struct.Reg }
%struct.Reg = type { i32 }
%struct.SR = type { i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, [4 x i8] }

@__anvill_reg_R1 = internal local_unnamed_addr global i32 0
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
@__anvill_reg_N = internal local_unnamed_addr global i8 0
@__anvill_reg_C = internal local_unnamed_addr global i8 0
@__anvill_reg_Z = internal local_unnamed_addr global i8 0
@__anvill_reg_V = internal local_unnamed_addr global i8 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@llvm.compiler.used = appending global [1 x ptr] [ptr @sub_0__Avi_B_0], section "llvm.metadata"
@__anvill_stack_0 = global i8 0
@__anvill_stack_plus_1 = global i8 0
@__anvill_stack_plus_2 = global i8 0
@__anvill_stack_plus_3 = global i8 0

; Function Attrs: noinline
define i32 @sub_0__Avi_B_0() #0 {
  %1 = alloca i32, align 4
  %tmpcast = bitcast ptr %1 to ptr
  %2 = bitcast ptr %1 to ptr
  %3 = load i8, ptr @__anvill_stack_0, align 1
  store i8 %3, ptr %2, align 4
  %4 = getelementptr inbounds %sub_0__Avi_B_0.frame_type_part0, ptr %tmpcast, i32 0, i32 0, i32 1
  %5 = load i8, ptr @__anvill_stack_plus_1, align 1
  store i8 %5, ptr %4, align 1
  %6 = getelementptr inbounds %sub_0__Avi_B_0.frame_type_part0, ptr %tmpcast, i32 0, i32 0, i32 2
  %7 = load i8, ptr @__anvill_stack_plus_2, align 1
  store i8 %7, ptr %6, align 2
  %8 = getelementptr inbounds %sub_0__Avi_B_0.frame_type_part0, ptr %tmpcast, i32 0, i32 0, i32 3
  %9 = load i8, ptr @__anvill_stack_plus_3, align 1
  store i8 %9, ptr %8, align 1
  %10 = alloca %struct.State, align 8
  %11 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 0, i32 0
  store i32 0, ptr %11, align 8
  %12 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 0, i32 1
  store i32 0, ptr %12, align 4
  %13 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 0, i32 2, i32 0
  store i64 0, ptr %13, align 8
  %14 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 0
  store i32 0, ptr %14, align 8
  %15 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 1, i32 0
  store i32 0, ptr %15, align 4
  %16 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 2
  store i32 0, ptr %16, align 8
  %17 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 3, i32 0
  %18 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 4
  store i32 0, ptr %18, align 8
  %19 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 5, i32 0
  store i32 0, ptr %19, align 4
  %20 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 6
  store i32 0, ptr %20, align 8
  %21 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 7, i32 0
  %22 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 8
  store i32 0, ptr %22, align 8
  %23 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 9, i32 0
  %24 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 10
  store i32 0, ptr %24, align 8
  %25 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 11, i32 0
  %26 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 12
  store i32 0, ptr %26, align 8
  %27 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 13, i32 0
  %28 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 14
  store i32 0, ptr %28, align 8
  %29 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 15, i32 0
  %30 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 16
  store i32 0, ptr %30, align 8
  %31 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 17, i32 0
  %32 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 18
  store i32 0, ptr %32, align 8
  %33 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 19, i32 0
  %34 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 20
  store i32 0, ptr %34, align 8
  %35 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 21, i32 0
  %36 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 22
  store i32 0, ptr %36, align 8
  %37 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 23, i32 0
  %38 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 24
  store i32 0, ptr %38, align 8
  %39 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 25, i32 0
  %40 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 26
  store i32 0, ptr %40, align 8
  %41 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 27, i32 0
  %42 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 28
  store i32 0, ptr %42, align 8
  %43 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 29, i32 0
  %44 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 30
  store i32 0, ptr %44, align 8
  %45 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 1, i32 31, i32 0
  %46 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 0
  store i8 0, ptr %46, align 8
  %47 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 1
  %48 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 2
  store i8 0, ptr %48, align 2
  %49 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 3
  %50 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 4
  store i8 0, ptr %50, align 4
  %51 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 5
  %52 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 6
  store i8 0, ptr %52, align 2
  %53 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 7
  %54 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 8
  store i8 0, ptr %54, align 8
  %55 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 9
  store i8 0, ptr %55, align 1
  %56 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 10
  store i8 0, ptr %56, align 2
  %57 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 11
  store i8 0, ptr %57, align 1
  %58 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 12
  store i8 0, ptr %58, align 4
  %59 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 13
  store i8 0, ptr %59, align 1
  %60 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 14
  store i8 0, ptr %60, align 2
  %61 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 15
  store i8 0, ptr %61, align 1
  %62 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 16
  store i8 0, ptr %62, align 8
  %63 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 17
  store i8 0, ptr %63, align 1
  %64 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 18
  store i8 0, ptr %64, align 2
  %65 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 19
  store i8 0, ptr %65, align 1
  %66 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 20, i32 0
  store i8 0, ptr %66, align 4
  %67 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 20, i32 1
  store i8 0, ptr %67, align 1
  %68 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 20, i32 2
  store i8 0, ptr %68, align 2
  %69 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 2, i32 20, i32 3
  store i8 0, ptr %69, align 1
  %70 = getelementptr inbounds %struct.State, ptr %10, i32 0, i32 3
  store i64 0, ptr %70, align 8
  %71 = load i32, ptr @__anvill_reg_R1, align 4
  store i32 %71, ptr %17, align 4
  %72 = load i32, ptr @__anvill_reg_R3, align 4
  store i32 %72, ptr %21, align 4
  %73 = load i32, ptr @__anvill_reg_R4, align 4
  store i32 %73, ptr %23, align 4
  %74 = load i32, ptr @__anvill_reg_R5, align 4
  store i32 %74, ptr %25, align 4
  %75 = load i32, ptr @__anvill_reg_R6, align 4
  store i32 %75, ptr %27, align 4
  %76 = load i32, ptr @__anvill_reg_R7, align 4
  store i32 %76, ptr %29, align 4
  %77 = load i32, ptr @__anvill_reg_R8, align 4
  store i32 %77, ptr %31, align 4
  %78 = load i32, ptr @__anvill_reg_R9, align 4
  store i32 %78, ptr %33, align 4
  %79 = load i32, ptr @__anvill_reg_R10, align 4
  store i32 %79, ptr %35, align 4
  %80 = load i32, ptr @__anvill_reg_R11, align 4
  store i32 %80, ptr %37, align 4
  %81 = load i32, ptr @__anvill_reg_R12, align 4
  store i32 %81, ptr %39, align 4
  %82 = load i8, ptr @__anvill_reg_N, align 1
  store i8 %82, ptr %47, align 1
  %83 = load i8, ptr @__anvill_reg_C, align 1
  store i8 %83, ptr %51, align 1
  %84 = load i8, ptr @__anvill_reg_Z, align 1
  store i8 %84, ptr %49, align 1
  %85 = load i8, ptr @__anvill_reg_V, align 1
  store i8 %85, ptr %53, align 1
  %86 = ptrtoint ptr %1 to i32
  store i32 %86, ptr %41, align 4
  store i32 ptrtoint (ptr @__anvill_ra to i32), ptr %43, align 4
  store i32 ptrtoint (ptr @__anvill_ra to i32), ptr %1, align 4
  store i32 0, ptr %15, align 4
  store i32 ptrtoint (ptr @__anvill_ra to i32), ptr %19, align 4
  store i32 ptrtoint (ptr @__anvill_ra to i32), ptr %45, align 4
  %87 = call ptr @__remill_jump(ptr %10, i32 ptrtoint (ptr @__anvill_ra to i32), ptr null)
  %88 = load i32, ptr %15, align 4
  ret i32 %88
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare ptr @__remill_write_memory_32(ptr, i32, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare i32 @__remill_read_memory_32(ptr, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_jump(ptr nonnull align 1, i32, ptr) local_unnamed_addr #2

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
