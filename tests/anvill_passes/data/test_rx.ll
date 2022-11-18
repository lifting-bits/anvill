; ModuleID = 'test_rx.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@llvm.compiler.used = appending global [45 x ptr] [ptr @strcpy, ptr @puts, ptr @setsockopt, ptr @write, ptr @clock, ptr @ctime, ptr @printf, ptr @snprintf, ptr @lseek, ptr @ioctl, ptr @read, ptr @fprintf, ptr @time, ptr @select, ptr @malloc, ptr @bind, ptr @open, ptr @fopen, ptr @perror, ptr @sleep, ptr @socket, ptr @sub_4011a4__All_Svl_B_0, ptr @rx_brake_routine, ptr @__libc_start_main, ptr @bind.16, ptr @clock.5, ptr @ctime.6, ptr @fopen.18, ptr @fprintf.12, ptr @ioctl.10, ptr @lseek.9, ptr @malloc.15, ptr @open.17, ptr @perror.19, ptr @printf.7, ptr @puts.2, ptr @read.11, ptr @select.14, ptr @setsockopt.3, ptr @sleep.20, ptr @snprintf.8, ptr @socket.21, ptr @strcpy.1, ptr @time.13, ptr @write.4], section "llvm.metadata"
@__anvill_stack_0 = global i8 0
@__anvill_stack_plus_1 = global i8 0
@__anvill_stack_plus_2 = global i8 0
@__anvill_stack_plus_3 = global i8 0
@__anvill_stack_plus_4 = global i8 0
@__anvill_stack_plus_5 = global i8 0
@__anvill_stack_plus_6 = global i8 0
@__anvill_stack_plus_7 = global i8 0

; Function Attrs: noinline
declare i64 @sub_4011a4__All_Svl_B_0(i64, i64, ptr) #0

; Function Attrs: noinline
declare ptr @strcpy(ptr, ptr) #0

; Function Attrs: noinline
declare i32 @puts(ptr) #0

; Function Attrs: noinline
declare i32 @setsockopt(i32, i32, i32, ptr, i32) #0

; Function Attrs: noinline
declare i64 @write(i32, ptr, i64) #0

; Function Attrs: noinline
declare i64 @clock() #0

; Function Attrs: noinline
declare ptr @ctime(ptr) #0

; Function Attrs: noinline
declare i32 @printf(ptr, ...) #0

; Function Attrs: noinline
declare i32 @snprintf(ptr, i64, ptr, ...) #0

; Function Attrs: noinline
declare i64 @lseek(i32, i64, i32) #0

; Function Attrs: noinline
declare i32 @ioctl(i32, i64, ...) #0

; Function Attrs: noinline
declare i64 @read(i32, ptr, i64) #0

; Function Attrs: noinline
declare i32 @fprintf(ptr, ptr, ...) #0

; Function Attrs: noinline
declare i64 @time(ptr) #0

; Function Attrs: noinline
declare i32 @select(i32, ptr, ptr, ptr, ptr) #0

; Function Attrs: noinline
declare i64 @malloc(i64) #0

; Function Attrs: noinline
declare i32 @bind(i32, ptr, i32) #0

; Function Attrs: noinline
declare i32 @open(ptr, i32, ...) #0

; Function Attrs: noinline
declare ptr @fopen(ptr, ptr) #0

; Function Attrs: noinline
declare void @perror(ptr) #0

; Function Attrs: noinline
declare i32 @sleep(i32) #0

; Function Attrs: noinline
declare i32 @socket(i32, i32, i32) #0

; Function Attrs: noinline
define i64 @rx_brake_routine(ptr %0, ptr %1) #0 {
  %3 = ptrtoint ptr %0 to i64
  %4 = ptrtoint ptr %1 to i64
  %5 = add i64 %3, 3
  %6 = inttoptr i64 %5 to ptr
  %7 = load i8, ptr %6, align 1
  %8 = add i64 %3, 4
  %9 = inttoptr i64 %8 to ptr
  %10 = load i8, ptr %9, align 1
  %11 = and i8 %10, 12
  %12 = icmp eq i8 %11, 0
  %13 = add i64 %4, 5
  %14 = xor i1 %12, true
  %15 = zext i1 %14 to i8
  %16 = inttoptr i64 %13 to ptr
  store i8 %15, ptr %16, align 1
  br i1 %12, label %17, label %23

17:                                               ; preds = %2
  %18 = zext i8 %7 to i64
  %19 = add i64 %4, 6
  %20 = inttoptr i64 %19 to ptr
  store i8 0, ptr %20, align 1
  %21 = add i64 %4, 4
  %22 = inttoptr i64 %21 to ptr
  store i8 0, ptr %22, align 1
  br label %41

23:                                               ; preds = %2
  %24 = add i64 %3, 2
  %25 = inttoptr i64 %24 to ptr
  %26 = load i8, ptr %25, align 1
  %27 = zext i8 %7 to i64
  %28 = shl nuw nsw i64 %27, 8
  %29 = zext i8 %26 to i64
  %30 = or i64 %28, %29
  %31 = icmp eq i64 %30, 0
  br i1 %31, label %37, label %32

32:                                               ; preds = %23
  %33 = add i64 %4, 4
  %34 = inttoptr i64 %33 to ptr
  %35 = load i8, ptr %34, align 1
  %36 = icmp eq i8 %35, 0
  br i1 %36, label %38, label %37

37:                                               ; preds = %32, %23
  br label %41

38:                                               ; preds = %32
  %39 = add i64 %4, 6
  %40 = inttoptr i64 %39 to ptr
  store i8 1, ptr %40, align 1
  br label %41

41:                                               ; preds = %38, %37, %17
  %42 = phi i64 [ %18, %17 ], [ %30, %37 ], [ %30, %38 ]
  ret i64 %42
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_64(ptr, i64, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local zeroext i8 @__remill_read_memory_8(ptr, i64) local_unnamed_addr #1

; Function Attrs: readnone
declare ptr @__anvill_type_hint_Sb(i64) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_8(ptr, i64, i8 zeroext) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local ptr @__remill_function_return(ptr nonnull align 1, i64, ptr) local_unnamed_addr #3

; Function Attrs: noinline
declare x86_64_sysvcc i32 @__libc_start_main(ptr, i32, ptr, ptr, ptr, ptr, ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc ptr @strcpy.1(ptr, ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @puts.2(ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @setsockopt.3(i32, i32, i32, ptr, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @write.4(i32, ptr, i64) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @clock.5() #0

; Function Attrs: noinline
declare x86_64_sysvcc ptr @ctime.6(ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @printf.7(ptr, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @snprintf.8(ptr, i64, ptr, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @lseek.9(i32, i64, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @ioctl.10(i32, i64, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @read.11(i32, ptr, i64) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @fprintf.12(ptr, ptr, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @time.13(ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @select.14(i32, ptr, ptr, ptr, ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc ptr @malloc.15(i64) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @bind.16(i32, ptr, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @open.17(ptr, i32, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc ptr @fopen.18(ptr, ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc void @perror.19(ptr) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sleep.20(i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @socket.21(i32, i32, i32) #0

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { readnone }
attributes #3 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
