; ModuleID = 'jmp0.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

@__anvill_reg_RAX = internal local_unnamed_addr global i64 0
@__anvill_reg_RBX = internal local_unnamed_addr global i64 0
@__anvill_reg_RCX = internal local_unnamed_addr global i64 0
@__anvill_reg_RDX = internal local_unnamed_addr global i64 0
@__anvill_reg_RSI = internal local_unnamed_addr global i64 0
@__anvill_reg_RDI = internal local_unnamed_addr global i64 0
@__anvill_reg_RBP = internal local_unnamed_addr global i64 0
@__anvill_reg_RIP = internal local_unnamed_addr global i64 0
@__anvill_reg_R8 = internal local_unnamed_addr global i64 0
@__anvill_reg_R9 = internal local_unnamed_addr global i64 0
@__anvill_reg_R10 = internal local_unnamed_addr global i64 0
@__anvill_reg_R11 = internal local_unnamed_addr global i64 0
@__anvill_reg_R12 = internal local_unnamed_addr global i64 0
@__anvill_reg_R13 = internal local_unnamed_addr global i64 0
@__anvill_reg_R14 = internal local_unnamed_addr global i64 0
@__anvill_reg_R15 = internal local_unnamed_addr global i64 0
@__anvill_reg_SS = internal local_unnamed_addr global i16 0
@__anvill_reg_ES = internal local_unnamed_addr global i16 0
@__anvill_reg_GS = internal local_unnamed_addr global i16 0
@__anvill_reg_FS = internal local_unnamed_addr global i16 0
@__anvill_reg_DS = internal local_unnamed_addr global i16 0
@__anvill_reg_CS = internal local_unnamed_addr global i16 0
@__anvill_reg_GS_BASE = internal local_unnamed_addr global i64 0
@__anvill_reg_FS_BASE = internal local_unnamed_addr global i64 0
@__anvill_reg_XMM0 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM1 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM2 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM3 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM4 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM5 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM6 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM7 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM8 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM9 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM10 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM11 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM12 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM13 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM14 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM15 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_ST0 = internal local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST1 = internal local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST2 = internal local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST3 = internal local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST4 = internal local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST5 = internal local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST6 = internal local_unnamed_addr global double 0.000000e+00
@__anvill_reg_ST7 = internal local_unnamed_addr global double 0.000000e+00
@__anvill_reg_MM0 = internal local_unnamed_addr global i64 0
@__anvill_reg_MM1 = internal local_unnamed_addr global i64 0
@__anvill_reg_MM2 = internal local_unnamed_addr global i64 0
@__anvill_reg_MM3 = internal local_unnamed_addr global i64 0
@__anvill_reg_MM4 = internal local_unnamed_addr global i64 0
@__anvill_reg_MM5 = internal local_unnamed_addr global i64 0
@__anvill_reg_MM6 = internal local_unnamed_addr global i64 0
@__anvill_reg_MM7 = internal local_unnamed_addr global i64 0
@__anvill_reg_AF = internal local_unnamed_addr global i8 0
@__anvill_reg_CF = internal local_unnamed_addr global i8 0
@__anvill_reg_DF = internal local_unnamed_addr global i8 0
@__anvill_reg_OF = internal local_unnamed_addr global i8 0
@__anvill_reg_PF = internal local_unnamed_addr global i8 0
@__anvill_reg_SF = internal local_unnamed_addr global i8 0
@__anvill_reg_ZF = internal local_unnamed_addr global i8 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@llvm.compiler.used = appending global [1 x ptr] [ptr @sub_0__Avl_B_0], section "llvm.metadata"
@__anvill_stack_0 = global i8 0
@__anvill_stack_plus_1 = global i8 0
@__anvill_stack_plus_2 = global i8 0
@__anvill_stack_plus_3 = global i8 0
@__anvill_stack_plus_4 = global i8 0
@__anvill_stack_plus_5 = global i8 0
@__anvill_stack_plus_6 = global i8 0
@__anvill_stack_plus_7 = global i8 0
@__anvill_stack_plus_8 = global i8 0
@__anvill_stack_plus_9 = global i8 0
@__anvill_stack_plus_10 = global i8 0
@__anvill_stack_plus_11 = global i8 0
@__anvill_stack_plus_12 = global i8 0
@__anvill_stack_plus_13 = global i8 0
@__anvill_stack_plus_14 = global i8 0
@__anvill_stack_plus_15 = global i8 0

; Function Attrs: noinline
define i64 @sub_0__Avl_B_0() #0 {
  ret i64 8
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_64(ptr, i64, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_function_return(ptr, i64, ptr) #2

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone }
