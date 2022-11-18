; ModuleID = 'RecoverStackFrameInformation.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"
target triple = "i386-pc-linux-gnu-elf"

@__anvill_sp = external global i8
@__anvill_ra = external global i8
@__anvill_pc = external global i8

; Function Attrs: noinline
declare i32 @sub_80483f0__Ai_Sii_B_0(i32, ptr) local_unnamed_addr #0

; Function Attrs: noinline
define i32 @sub_80482e0__Ai_S_Sb_S_Sbi_B_0(i32 %0, ptr %1, ptr %2) local_unnamed_addr #0 {
  store i32 ptrtoint (ptr @__anvill_ra to i32), ptr inttoptr (i32 ptrtoint (ptr @__anvill_sp to i32) to ptr), align 4
  store i32 %0, ptr inttoptr (i32 add (i32 ptrtoint (ptr @__anvill_sp to i32), i32 4) to ptr), align 4
  %4 = ptrtoint ptr %1 to i32
  store i32 %4, ptr inttoptr (i32 add (i32 ptrtoint (ptr @__anvill_sp to i32), i32 8) to ptr), align 4
  %5 = ptrtoint ptr %2 to i32
  store i32 %5, ptr inttoptr (i32 add (i32 ptrtoint (ptr @__anvill_sp to i32), i32 12) to ptr), align 4
  %6 = load i32, ptr inttoptr (i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 20) to ptr), align 4
  store i32 %6, ptr inttoptr (i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 12) to ptr), align 4
  store i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 12), ptr inttoptr (i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 -4) to ptr), align 4
  store i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 12), ptr inttoptr (i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 -8) to ptr), align 4
  store i32 add (i32 ptrtoint (ptr @__anvill_pc to i32), i32 134513398), ptr inttoptr (i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 -12) to ptr), align 4
  %7 = load i32, ptr inttoptr (i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 -8) to ptr), align 4
  %8 = load i32, ptr inttoptr (i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 -4) to ptr), align 4
  %9 = inttoptr i32 %8 to ptr
  %10 = call i32 @sub_80483f0__Ai_Sii_B_0(i32 %7, ptr %9)
  %11 = load i32, ptr inttoptr (i32 add (i32 sub (i32 ptrtoint (ptr @__anvill_sp to i32), i32 16), i32 16) to ptr), align 4
  %12 = call ptr @__remill_function_return(ptr undef, i32 %11, ptr null)
  ret i32 %10
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_32(ptr, i32, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i32 @__remill_read_memory_32(ptr, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local ptr @__remill_function_return(ptr nonnull align 1, i32, ptr) local_unnamed_addr #2

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
