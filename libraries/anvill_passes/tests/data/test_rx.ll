; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

%anvill.struct.0 = type { i32, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, %anvill.struct.1*, %anvill.struct.0*, i32, i32, i64, i16, i8, [1 x i8], %anvill.struct.2*, i64, %anvill.struct.3*, %anvill.struct.10*, %anvill.struct.0*, i8*, i64, i32, [20 x i8] }
%anvill.struct.1 = type { %anvill.struct.1*, %anvill.struct.0*, i32 }
%anvill.struct.2 = type { i32, i32, i8* }
%anvill.struct.3 = type { %anvill.struct.4, %anvill.struct.4 }
%anvill.struct.4 = type { %anvill.struct.5*, %anvill.struct.7 }
%anvill.struct.5 = type { %anvill.struct.6*, i8*, i32, i8*, i8*, i32 (%anvill.struct.5*, %anvill.struct.7*, i8**, i8*, i8**, i64*, i32, i32)*, i32 (%anvill.struct.5*, i8)*, i32 (%anvill.struct.5*)*, void (%anvill.struct.5*)*, i32, i32, i32, i32, i32, i8* }
%anvill.struct.6 = type { i8*, i32, i8*, i32 (%anvill.struct.5*, %anvill.struct.7*, i8**, i8*, i8**, i64*, i32, i32)*, i32 (%anvill.struct.5*)*, void (%anvill.struct.5*)* }
%anvill.struct.7 = type { i8*, i8*, i32, i32, i32, %anvill.struct.8*, %anvill.struct.8 }
%anvill.struct.8 = type { i32, %anvill.struct.9 }
%anvill.struct.9 = type { [4 x i8] }
%anvill.struct.10 = type { i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, %anvill.struct.8, %anvill.struct.8, %anvill.struct.3, [1 x i32], %anvill.struct.11* }
%anvill.struct.11 = type { i64, i64, void (%anvill.struct.0*, i32)*, i32 (%anvill.struct.0*, i32)*, i32 (%anvill.struct.0*)*, i32 (%anvill.struct.0*)*, i32 (%anvill.struct.0*, i32)*, i64 (%anvill.struct.0*, i8*, i64)*, i64 (%anvill.struct.0*, i8*, i64)*, i64 (%anvill.struct.0*, i64, i32, i32)*, i64 (%anvill.struct.0*, i64, i32)*, %anvill.struct.0* (%anvill.struct.0*, i8*, i64)*, i32 (%anvill.struct.0*)*, i32 (%anvill.struct.0*)*, i64 (%anvill.struct.0*, i8*, i64)*, i64 (%anvill.struct.0*, i8*, i64)*, i64 (%anvill.struct.0*, i64, i32)*, i32 (%anvill.struct.0*)*, i32 (%anvill.struct.0*, i8*)*, i32 (%anvill.struct.0*)*, void (%anvill.struct.0*, i8*)* }
%anvill.struct.0.0 = type { [16 x i64] }
%anvill.struct.0.1 = type { [16 x i64] }
%anvill.struct.0.2 = type { [16 x i64] }
%anvill.struct.0.3 = type { i64, i64 }
%anvill.struct.0.4 = type { i16, [14 x i8] }
%anvill.struct.0.5 = type { i32, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, %anvill.struct.1.6*, %anvill.struct.0.5*, i32, i32, i64, i16, i8, [1 x i8], %anvill.struct.2.7*, i64, %anvill.struct.3.8*, %anvill.struct.10.15*, %anvill.struct.0.5*, i8*, i64, i32, [20 x i8] }
%anvill.struct.1.6 = type { %anvill.struct.1.6*, %anvill.struct.0.5*, i32 }
%anvill.struct.2.7 = type { i32, i32, i8* }
%anvill.struct.3.8 = type { %anvill.struct.4.9, %anvill.struct.4.9 }
%anvill.struct.4.9 = type { %anvill.struct.5.10*, %anvill.struct.7.12 }
%anvill.struct.5.10 = type { %anvill.struct.6.11*, i8*, i32, i8*, i8*, i32 (%anvill.struct.5.10*, %anvill.struct.7.12*, i8**, i8*, i8**, i64*, i32, i32)*, i32 (%anvill.struct.5.10*, i8)*, i32 (%anvill.struct.5.10*)*, void (%anvill.struct.5.10*)*, i32, i32, i32, i32, i32, i8* }
%anvill.struct.6.11 = type { i8*, i32, i8*, i32 (%anvill.struct.5.10*, %anvill.struct.7.12*, i8**, i8*, i8**, i64*, i32, i32)*, i32 (%anvill.struct.5.10*)*, void (%anvill.struct.5.10*)* }
%anvill.struct.7.12 = type { i8*, i8*, i32, i32, i32, %anvill.struct.8.13*, %anvill.struct.8.13 }
%anvill.struct.8.13 = type { i32, %anvill.struct.9.14 }
%anvill.struct.9.14 = type { [4 x i8] }
%anvill.struct.10.15 = type { i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, %anvill.struct.8.13, %anvill.struct.8.13, %anvill.struct.3.8, [1 x i32], %anvill.struct.11.16* }
%anvill.struct.11.16 = type { i64, i64, void (%anvill.struct.0.5*, i32)*, i32 (%anvill.struct.0.5*, i32)*, i32 (%anvill.struct.0.5*)*, i32 (%anvill.struct.0.5*)*, i32 (%anvill.struct.0.5*, i32)*, i64 (%anvill.struct.0.5*, i8*, i64)*, i64 (%anvill.struct.0.5*, i8*, i64)*, i64 (%anvill.struct.0.5*, i64, i32, i32)*, i64 (%anvill.struct.0.5*, i64, i32)*, %anvill.struct.0.5* (%anvill.struct.0.5*, i8*, i64)*, i32 (%anvill.struct.0.5*)*, i32 (%anvill.struct.0.5*)*, i64 (%anvill.struct.0.5*, i8*, i64)*, i64 (%anvill.struct.0.5*, i8*, i64)*, i64 (%anvill.struct.0.5*, i64, i32)*, i32 (%anvill.struct.0.5*)*, i32 (%anvill.struct.0.5*, i8*)*, i32 (%anvill.struct.0.5*)*, void (%anvill.struct.0.5*, i8*)* }
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
%anvill.struct.0.17 = type { i32, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, %anvill.struct.1.18*, %anvill.struct.0.17*, i32, i32, i64, i16, i8, [1 x i8], %anvill.struct.2.19*, i64, %anvill.struct.3.20*, %anvill.struct.10.27*, %anvill.struct.0.17*, i8*, i64, i32, [20 x i8] }
%anvill.struct.1.18 = type { %anvill.struct.1.18*, %anvill.struct.0.17*, i32 }
%anvill.struct.2.19 = type { i32, i32, i8* }
%anvill.struct.3.20 = type { %anvill.struct.4.21, %anvill.struct.4.21 }
%anvill.struct.4.21 = type { %anvill.struct.5.22*, %anvill.struct.7.24 }
%anvill.struct.5.22 = type { %anvill.struct.6.23*, i8*, i32, i8*, i8*, i32 (%anvill.struct.5.22*, %anvill.struct.7.24*, i8**, i8*, i8**, i64*, i32, i32)*, i32 (%anvill.struct.5.22*, i8)*, i32 (%anvill.struct.5.22*)*, void (%anvill.struct.5.22*)*, i32, i32, i32, i32, i32, i8* }
%anvill.struct.6.23 = type { i8*, i32, i8*, i32 (%anvill.struct.5.22*, %anvill.struct.7.24*, i8**, i8*, i8**, i64*, i32, i32)*, i32 (%anvill.struct.5.22*)*, void (%anvill.struct.5.22*)* }
%anvill.struct.7.24 = type { i8*, i8*, i32, i32, i32, %anvill.struct.8.25*, %anvill.struct.8.25 }
%anvill.struct.8.25 = type { i32, %anvill.struct.9.26 }
%anvill.struct.9.26 = type { [4 x i8] }
%anvill.struct.10.27 = type { i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, %anvill.struct.8.25, %anvill.struct.8.25, %anvill.struct.3.20, [1 x i32], %anvill.struct.11.28* }
%anvill.struct.11.28 = type { i64, i64, void (%anvill.struct.0.17*, i32)*, i32 (%anvill.struct.0.17*, i32)*, i32 (%anvill.struct.0.17*)*, i32 (%anvill.struct.0.17*)*, i32 (%anvill.struct.0.17*, i32)*, i64 (%anvill.struct.0.17*, i8*, i64)*, i64 (%anvill.struct.0.17*, i8*, i64)*, i64 (%anvill.struct.0.17*, i64, i32, i32)*, i64 (%anvill.struct.0.17*, i64, i32)*, %anvill.struct.0.17* (%anvill.struct.0.17*, i8*, i64)*, i32 (%anvill.struct.0.17*)*, i32 (%anvill.struct.0.17*)*, i64 (%anvill.struct.0.17*, i8*, i64)*, i64 (%anvill.struct.0.17*, i8*, i64)*, i64 (%anvill.struct.0.17*, i64, i32)*, i32 (%anvill.struct.0.17*)*, i32 (%anvill.struct.0.17*, i8*)*, i32 (%anvill.struct.0.17*)*, void (%anvill.struct.0.17*, i8*)* }
%anvill.struct.0.29 = type { [16 x i64] }
%anvill.struct.1.30 = type { i64, i64 }
%anvill.struct.0.31 = type { i16, [14 x i8] }
%anvill.struct.0.32 = type { i32, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, %anvill.struct.1.33*, %anvill.struct.0.32*, i32, i32, i64, i16, i8, [1 x i8], %anvill.struct.2.34*, i64, %anvill.struct.3.35*, %anvill.struct.10.42*, %anvill.struct.0.32*, i8*, i64, i32, [20 x i8] }
%anvill.struct.1.33 = type { %anvill.struct.1.33*, %anvill.struct.0.32*, i32 }
%anvill.struct.2.34 = type { i32, i32, i8* }
%anvill.struct.3.35 = type { %anvill.struct.4.36, %anvill.struct.4.36 }
%anvill.struct.4.36 = type { %anvill.struct.5.37*, %anvill.struct.7.39 }
%anvill.struct.5.37 = type { %anvill.struct.6.38*, i8*, i32, i8*, i8*, i32 (%anvill.struct.5.37*, %anvill.struct.7.39*, i8**, i8*, i8**, i64*, i32, i32)*, i32 (%anvill.struct.5.37*, i8)*, i32 (%anvill.struct.5.37*)*, void (%anvill.struct.5.37*)*, i32, i32, i32, i32, i32, i8* }
%anvill.struct.6.38 = type { i8*, i32, i8*, i32 (%anvill.struct.5.37*, %anvill.struct.7.39*, i8**, i8*, i8**, i64*, i32, i32)*, i32 (%anvill.struct.5.37*)*, void (%anvill.struct.5.37*)* }
%anvill.struct.7.39 = type { i8*, i8*, i32, i32, i32, %anvill.struct.8.40*, %anvill.struct.8.40 }
%anvill.struct.8.40 = type { i32, %anvill.struct.9.41 }
%anvill.struct.9.41 = type { [4 x i8] }
%anvill.struct.10.42 = type { i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, i32*, %anvill.struct.8.40, %anvill.struct.8.40, %anvill.struct.3.35, [1 x i32], %anvill.struct.11.43* }
%anvill.struct.11.43 = type { i64, i64, void (%anvill.struct.0.32*, i32)*, i32 (%anvill.struct.0.32*, i32)*, i32 (%anvill.struct.0.32*)*, i32 (%anvill.struct.0.32*)*, i32 (%anvill.struct.0.32*, i32)*, i64 (%anvill.struct.0.32*, i8*, i64)*, i64 (%anvill.struct.0.32*, i8*, i64)*, i64 (%anvill.struct.0.32*, i64, i32, i32)*, i64 (%anvill.struct.0.32*, i64, i32)*, %anvill.struct.0.32* (%anvill.struct.0.32*, i8*, i64)*, i32 (%anvill.struct.0.32*)*, i32 (%anvill.struct.0.32*)*, i64 (%anvill.struct.0.32*, i8*, i64)*, i64 (%anvill.struct.0.32*, i8*, i64)*, i64 (%anvill.struct.0.32*, i64, i32)*, i32 (%anvill.struct.0.32*)*, i32 (%anvill.struct.0.32*, i8*)*, i32 (%anvill.struct.0.32*)*, void (%anvill.struct.0.32*, i8*)* }

@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@llvm.compiler.used = appending global [45 x i8*] [i8* bitcast (i8* (i8*, i8*)* @strcpy to i8*), i8* bitcast (i32 (i8*)* @puts to i8*), i8* bitcast (i32 (i32, i32, i32, i8*, i32)* @setsockopt to i8*), i8* bitcast (i64 (i32, i8*, i64)* @write to i8*), i8* bitcast (i64 ()* @clock to i8*), i8* bitcast (i8* (i64*)* @ctime to i8*), i8* bitcast (i32 (i8*, ...)* @printf to i8*), i8* bitcast (i32 (i8*, i64, i8*, ...)* @snprintf to i8*), i8* bitcast (i64 (i32, i64, i32)* @lseek to i8*), i8* bitcast (i32 (i32, i64, ...)* @ioctl to i8*), i8* bitcast (i64 (i32, i8*, i64)* @read to i8*), i8* bitcast (i32 (%anvill.struct.0*, i8*, ...)* @fprintf to i8*), i8* bitcast (i64 (i64*)* @time to i8*), i8* bitcast (i32 (i32, %anvill.struct.0.0*, %anvill.struct.0.1*, %anvill.struct.0.2*, %anvill.struct.0.3*)* @select to i8*), i8* bitcast (i64 (i64)* @malloc to i8*), i8* bitcast (i32 (i32, %anvill.struct.0.4*, i32)* @bind to i8*), i8* bitcast (i32 (i8*, i32, ...)* @open to i8*), i8* bitcast (%anvill.struct.0.5* (i8*, i8*)* @fopen to i8*), i8* bitcast (void (i8*)* @perror to i8*), i8* bitcast (i32 (i32)* @sleep to i8*), i8* bitcast (i32 (i32, i32, i32)* @socket to i8*), i8* bitcast (i64 (i64, i64, void ()*)* @sub_4011a4__All_Svl_B_0 to i8*), i8* bitcast (i64 (i8*, i8*)* @rx_brake_routine to i8*), i8* bitcast (i32 (i32 (i32, i8**, i8**)*, i32, i8**, i32 (i32, i8**, i8**)*, void ()*, void ()*, i8*)* @__libc_start_main to i8*), i8* bitcast (i32 (i32, %anvill.struct.0.31*, i32)* @bind.16 to i8*), i8* bitcast (i64 ()* @clock.5 to i8*), i8* bitcast (i8* (i64*)* @ctime.6 to i8*), i8* bitcast (%anvill.struct.0.32* (i8*, i8*)* @fopen.18 to i8*), i8* bitcast (i32 (%anvill.struct.0.17*, i8*, ...)* @fprintf.12 to i8*), i8* bitcast (i32 (i32, i64, ...)* @ioctl.10 to i8*), i8* bitcast (i64 (i32, i64, i32)* @lseek.9 to i8*), i8* bitcast (i8* (i64)* @malloc.15 to i8*), i8* bitcast (i32 (i8*, i32, ...)* @open.17 to i8*), i8* bitcast (void (i8*)* @perror.19 to i8*), i8* bitcast (i32 (i8*, ...)* @printf.7 to i8*), i8* bitcast (i32 (i8*)* @puts.2 to i8*), i8* bitcast (i64 (i32, i8*, i64)* @read.11 to i8*), i8* bitcast (i32 (i32, %anvill.struct.0.29*, %anvill.struct.0.29*, %anvill.struct.0.29*, %anvill.struct.1.30*)* @select.14 to i8*), i8* bitcast (i32 (i32, i32, i32, i8*, i32)* @setsockopt.3 to i8*), i8* bitcast (i32 (i32)* @sleep.20 to i8*), i8* bitcast (i32 (i8*, i64, i8*, ...)* @snprintf.8 to i8*), i8* bitcast (i32 (i32, i32, i32)* @socket.21 to i8*), i8* bitcast (i8* (i8*, i8*)* @strcpy.1 to i8*), i8* bitcast (i64 (i64*)* @time.13 to i8*), i8* bitcast (i64 (i32, i8*, i64)* @write.4 to i8*)], section "llvm.metadata"
@__anvill_stack_0 = global i8 0
@__anvill_stack_plus_1 = global i8 0
@__anvill_stack_plus_2 = global i8 0
@__anvill_stack_plus_3 = global i8 0
@__anvill_stack_plus_4 = global i8 0
@__anvill_stack_plus_5 = global i8 0
@__anvill_stack_plus_6 = global i8 0
@__anvill_stack_plus_7 = global i8 0

; Function Attrs: noinline
declare i64 @sub_4011a4__All_Svl_B_0(i64, i64, void ()*) #0

; Function Attrs: noinline
declare i8* @strcpy(i8*, i8*) #0

; Function Attrs: noinline
declare i32 @puts(i8*) #0

; Function Attrs: noinline
declare i32 @setsockopt(i32, i32, i32, i8*, i32) #0

; Function Attrs: noinline
declare i64 @write(i32, i8*, i64) #0

; Function Attrs: noinline
declare i64 @clock() #0

; Function Attrs: noinline
declare i8* @ctime(i64*) #0

; Function Attrs: noinline
declare i32 @printf(i8*, ...) #0

; Function Attrs: noinline
declare i32 @snprintf(i8*, i64, i8*, ...) #0

; Function Attrs: noinline
declare i64 @lseek(i32, i64, i32) #0

; Function Attrs: noinline
declare i32 @ioctl(i32, i64, ...) #0

; Function Attrs: noinline
declare i64 @read(i32, i8*, i64) #0

; Function Attrs: noinline
declare i32 @fprintf(%anvill.struct.0*, i8*, ...) #0

; Function Attrs: noinline
declare i64 @time(i64*) #0

; Function Attrs: noinline
declare i32 @select(i32, %anvill.struct.0.0*, %anvill.struct.0.1*, %anvill.struct.0.2*, %anvill.struct.0.3*) #0

; Function Attrs: noinline
declare i64 @malloc(i64) #0

; Function Attrs: noinline
declare i32 @bind(i32, %anvill.struct.0.4*, i32) #0

; Function Attrs: noinline
declare i32 @open(i8*, i32, ...) #0

; Function Attrs: noinline
declare %anvill.struct.0.5* @fopen(i8*, i8*) #0

; Function Attrs: noinline
declare void @perror(i8*) #0

; Function Attrs: noinline
declare i32 @sleep(i32) #0

; Function Attrs: noinline
declare i32 @socket(i32, i32, i32) #0

; Function Attrs: noinline
define i64 @rx_brake_routine(i8* %0, i8* %1) #0 {
  %3 = ptrtoint i8* %0 to i64
  %4 = ptrtoint i8* %1 to i64
  %5 = add i64 %3, 3
  %6 = inttoptr i64 %5 to i8*
  %7 = load i8, i8* %6, align 1
  %8 = add i64 %3, 4
  %9 = inttoptr i64 %8 to i8*
  %10 = load i8, i8* %9, align 1
  %11 = and i8 %10, 12
  %12 = icmp eq i8 %11, 0
  %13 = add i64 %4, 5
  %14 = xor i1 %12, true
  %15 = zext i1 %14 to i8
  %16 = inttoptr i64 %13 to i8*
  store i8 %15, i8* %16, align 1
  br i1 %12, label %17, label %23

17:                                               ; preds = %2
  %18 = zext i8 %7 to i64
  %19 = add i64 %4, 6
  %20 = inttoptr i64 %19 to i8*
  store i8 0, i8* %20, align 1
  %21 = add i64 %4, 4
  %22 = inttoptr i64 %21 to i8*
  store i8 0, i8* %22, align 1
  br label %41

23:                                               ; preds = %2
  %24 = add i64 %3, 2
  %25 = inttoptr i64 %24 to i8*
  %26 = load i8, i8* %25, align 1
  %27 = zext i8 %7 to i64
  %28 = shl nuw nsw i64 %27, 8
  %29 = zext i8 %26 to i64
  %30 = or i64 %28, %29
  %31 = icmp eq i64 %30, 0
  br i1 %31, label %37, label %32

32:                                               ; preds = %23
  %33 = add i64 %4, 4
  %34 = inttoptr i64 %33 to i8*
  %35 = load i8, i8* %34, align 1
  %36 = icmp eq i8 %35, 0
  br i1 %36, label %38, label %37

37:                                               ; preds = %32, %23
  br label %41

38:                                               ; preds = %32
  %39 = add i64 %4, 6
  %40 = inttoptr i64 %39 to i8*
  store i8 1, i8* %40, align 1
  br label %41

41:                                               ; preds = %38, %37, %17
  %42 = phi i64 [ %18, %17 ], [ %30, %37 ], [ %30, %38 ]
  ret i64 %42
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_64(%struct.Memory*, i64, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local zeroext i8 @__remill_read_memory_8(%struct.Memory*, i64) local_unnamed_addr #1

; Function Attrs: readnone
declare i8* @__anvill_type_hint_Sb(i64) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_8(%struct.Memory*, i64, i8 zeroext) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(%struct.Memory*, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local %struct.Memory* @__remill_function_return(%struct.State* nonnull align 1, i64, %struct.Memory*) local_unnamed_addr #3

; Function Attrs: noinline
declare x86_64_sysvcc i32 @__libc_start_main(i32 (i32, i8**, i8**)*, i32, i8**, i32 (i32, i8**, i8**)*, void ()*, void ()*, i8*) #0

; Function Attrs: noinline
declare x86_64_sysvcc i8* @strcpy.1(i8*, i8*) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @puts.2(i8*) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @setsockopt.3(i32, i32, i32, i8*, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @write.4(i32, i8*, i64) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @clock.5() #0

; Function Attrs: noinline
declare x86_64_sysvcc i8* @ctime.6(i64*) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @printf.7(i8*, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @snprintf.8(i8*, i64, i8*, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @lseek.9(i32, i64, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @ioctl.10(i32, i64, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @read.11(i32, i8*, i64) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @fprintf.12(%anvill.struct.0.17*, i8*, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc i64 @time.13(i64*) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @select.14(i32, %anvill.struct.0.29*, %anvill.struct.0.29*, %anvill.struct.0.29*, %anvill.struct.1.30*) #0

; Function Attrs: noinline
declare x86_64_sysvcc i8* @malloc.15(i64) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @bind.16(i32, %anvill.struct.0.31*, i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @open.17(i8*, i32, ...) #0

; Function Attrs: noinline
declare x86_64_sysvcc %anvill.struct.0.32* @fopen.18(i8*, i8*) #0

; Function Attrs: noinline
declare x86_64_sysvcc void @perror.19(i8*) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @sleep.20(i32) #0

; Function Attrs: noinline
declare x86_64_sysvcc i32 @socket.21(i32, i32, i32) #0

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { readnone }
attributes #3 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
