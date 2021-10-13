; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

@var_402260__C_Cix3_Dx30_D = global [30 x [3 x i32]] [[3 x i32] [i32 0, i32 1996959894, i32 -285212673], [3 x i32] [i32 -1711276033, i32 124634367, i32 1886057727], [3 x i32] [i32 -369098753, i32 -1627389953, i32 249298943], [3 x i32] [i32 2044526591, i32 -520093697, i32 -1744830465], [3 x i32] [i32 162988031, i32 2125594623, i32 -402653185], [3 x i32] [i32 -1862270977, i32 498597887, i32 1789984767], [3 x i32] [i32 -201326593, i32 -2063597569, i32 450559999], [3 x i32] [i32 1843265535, i32 -184549377, i32 -2080374785], [3 x i32] [i32 325884159, i32 1684777215, i32 -33554433], [3 x i32] [i32 -1962934273, i32 335633487, i32 1661365465], [3 x i32] [i32 -83886081, i32 -1912602625, i32 997073096], [3 x i32] [i32 1281953886, i32 -704643073, i32 -1560281089], [3 x i32] [i32 1006888191, i32 1258607871, i32 -754974721], [3 x i32] [i32 -1509949441, i32 901119999, i32 1119027199], [3 x i32] [i32 -603979777, i32 -1392508929, i32 853082111], [3 x i32] [i32 1172307967, i32 -587202561, i32 -1409286145], [3 x i32] [i32 651821055, i32 1373569023, i32 -922746881], [3 x i32] [i32 -1073741825, i32 565510143, i32 1454637055], [3 x i32] [i32 -805306369, i32 -1191182337, i32 671267071], [3 x i32] [i32 1594198271, i32 -956301313, i32 -1308622849], [3 x i32] [i32 795835527, i32 1483230225, i32 -1040187393], [3 x i32] [i32 -1224736769, i32 1994194943, i32 31195135], [3 x i32] [i32 -1728053249, i32 -268435457, i32 1907490815], [3 x i32] [i32 112656383, i32 -1610612737, i32 -385875969], [3 x i32] [i32 2013776383, i32 251722239, i32 -1761607681], [3 x i32] [i32 -503316481, i32 2137656763, i32 141376813], [3 x i32] [i32 -1845493761, i32 -419430401, i32 1802195444], [3 x i32] [i32 476864866, i32 -2046820353, i32 -218103809], [3 x i32] [i32 1812370943, i32 453092863, i32 -2097152001], [3 x i32] [i32 -167772161, i32 1706098687, i32 314048511]]
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@__anvill_pc = internal global i8 0
@llvm.compiler.used = appending global [3 x i8*] [i8* bitcast (i64 (i8*, i32)* @sub_401b50__A_Sbil_B_0 to i8*), i8* bitcast ([30 x [3 x i32]]* @var_402260__C_Cix3_Dx30_D to i8*), i8* @data_402260_b], section "llvm.metadata"
@__anvill_stack_0 = global i8 0
@__anvill_stack_plus_1 = global i8 0
@__anvill_stack_plus_2 = global i8 0
@__anvill_stack_plus_3 = global i8 0
@__anvill_stack_plus_4 = global i8 0
@__anvill_stack_plus_5 = global i8 0
@__anvill_stack_plus_6 = global i8 0
@__anvill_stack_plus_7 = global i8 0

@data_402260_b = alias i8, bitcast ([30 x [3 x i32]]* @var_402260__C_Cix3_Dx30_D to i8*)

; Function Attrs: noinline
define i64 @sub_401b50__A_Sbil_B_0(i8* %0, i32 %1) #0 {
  %3 = icmp slt i32 %1, 1
  br i1 %3, label %4, label %5

4:                                                ; preds = %2
  br label %35

5:                                                ; preds = %2
  %6 = add i32 %1, -1
  %7 = zext i32 %6 to i64
  %8 = getelementptr i8, i8* %0, i64 1
  %9 = ptrtoint i8* %8 to i64
  %10 = sext i32 %6 to i64
  %11 = getelementptr i8, i8* %8, i64 %10
  %12 = add i64 %9, %7
  br label %13

13:                                               ; preds = %13, %5
  %14 = phi i64 [ %12, %5 ], [ %29, %13 ]
  %15 = phi i8* [ %0, %5 ], [ %19, %13 ]
  %16 = phi i8 [ -1, %5 ], [ %30, %13 ]
  %17 = phi i32 [ 16777215, %5 ], [ %31, %13 ]
  %18 = load i8, i8* %15, align 1
  %19 = getelementptr i8, i8* %15, i64 1
  %20 = ptrtoint i8* %19 to i64
  %21 = xor i8 %18, %16
  %22 = zext i8 %21 to i64
  %23 = shl nuw nsw i64 %22, 2
  %24 = add i64 %23, ptrtoint ([30 x [3 x i32]]* @var_402260__C_Cix3_Dx30_D to i64)
  %25 = inttoptr i64 %24 to i32*
  %26 = load i32, i32* %25, align 4
  %27 = xor i32 %26, %17
  %28 = icmp eq i64 %14, %20
  %29 = ptrtoint i8* %11 to i64
  %30 = trunc i32 %27 to i8
  %31 = lshr i32 %27, 8
  br i1 %28, label %32, label %13

32:                                               ; preds = %13
  %33 = xor i32 %27, -1
  %34 = zext i32 %33 to i64
  br label %35

35:                                               ; preds = %32, %4
  %36 = phi i64 [ 0, %4 ], [ %34, %32 ]
  ret i64 %36
}

attributes #0 = { noinline }