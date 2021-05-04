; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

%sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0 = type <{ [48 x i8] }>
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

@var_400654_h = global i16 1
@var_400656_b = global i8 11
@__anvill_reg_RBP = internal local_unnamed_addr global i64 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@__anvill_pc = internal global i8 0
@llvm.compiler.used = appending global [7 x i8*] [i8* bitcast (i64 (i64, i64, i32 ()*)* @sub_4003d4__All_Svl_B_0 to i8*), i8* bitcast (i8* (i8*)* @xor_swap to i8*), i8* bitcast (i64 (i8*)* @atoi to i8*), i8* bitcast (i32 (i32, i8**, i8**)* @main to i8*), i8* bitcast (i32 (i32 (i32, i8**, i8**)*, i32, i8**, i32 (i32, i8**, i8**)*, i32 ()*, i32 ()*, i8*)* @__libc_start_main to i8*), i8* bitcast (i16* @var_400654_h to i8*), i8* @var_400656_b], section "llvm.metadata"
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
declare i64 @sub_4003d4__All_Svl_B_0(i64, i64, i32 ()*) #0

; Function Attrs: noinline
define i32 @main(i32 %0, i8** %1, i8** %2) #0 {
  %4 = alloca %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, align 8
  %5 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 0
  %6 = load i8, i8* @__anvill_stack_minus_48, align 1
  store i8 %6, i8* %5, align 8
  %7 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 1
  %8 = load i8, i8* @__anvill_stack_minus_47, align 1
  store i8 %8, i8* %7, align 1
  %9 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 2
  %10 = load i8, i8* @__anvill_stack_minus_46, align 1
  store i8 %10, i8* %9, align 2
  %11 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 3
  %12 = load i8, i8* @__anvill_stack_minus_45, align 1
  store i8 %12, i8* %11, align 1
  %13 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 4
  %14 = load i8, i8* @__anvill_stack_minus_44, align 1
  store i8 %14, i8* %13, align 4
  %15 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 5
  %16 = load i8, i8* @__anvill_stack_minus_43, align 1
  store i8 %16, i8* %15, align 1
  %17 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 6
  %18 = load i8, i8* @__anvill_stack_minus_42, align 1
  store i8 %18, i8* %17, align 2
  %19 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 7
  %20 = load i8, i8* @__anvill_stack_minus_41, align 1
  store i8 %20, i8* %19, align 1
  %21 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 8
  %22 = load i8, i8* @__anvill_stack_minus_40, align 1
  store i8 %22, i8* %21, align 8
  %23 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 9
  %24 = load i8, i8* @__anvill_stack_minus_39, align 1
  store i8 %24, i8* %23, align 1
  %25 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 10
  %26 = load i8, i8* @__anvill_stack_minus_38, align 1
  store i8 %26, i8* %25, align 2
  %27 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 11
  %28 = load i8, i8* @__anvill_stack_minus_37, align 1
  store i8 %28, i8* %27, align 1
  %29 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 12
  %30 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 16
  %31 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 20
  %32 = load i8, i8* @__anvill_stack_minus_28, align 1
  store i8 %32, i8* %31, align 4
  %33 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 21
  %34 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 23
  %35 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 24
  %36 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 32
  %37 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 36
  %38 = getelementptr inbounds %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0, %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4, i64 0, i32 0, i64 40
  %39 = load i64, i64* @__anvill_reg_RBP, align 8
  %40 = ptrtoint i8** %1 to i64
  %41 = bitcast i8* %38 to i64*
  store i64 %39, i64* %41, align 8
  %42 = bitcast i8* %37 to i32*
  store i32 0, i32* %42, align 4
  %43 = bitcast i8* %36 to i32*
  store i32 %0, i32* %43, align 8
  %44 = bitcast i8* %35 to i64*
  store i64 %40, i64* %44, align 8
  %45 = load i16, i16* @var_400654_h, align 2
  %46 = bitcast i8* %33 to i16*
  store i16 %45, i16* %46, align 2
  %47 = load i8, i8* @var_400656_b, align 1
  store i8 %47, i8* %34, align 1
  %48 = bitcast i8* %30 to i32*
  store i32 3, i32* %48, align 8
  %49 = bitcast i8* %29 to i32*
  store i32 1, i32* %49, align 4
  br label %50

50:                                               ; preds = %86, %3
  %51 = phi i64 [ 4195674, %3 ], [ %106, %86 ]
  %52 = load i32, i32* %49, align 4
  %53 = load i32, i32* %43, align 8
  %54 = sub i32 %52, %53
  %55 = lshr i32 %54, 31
  %56 = lshr i32 %52, 31
  %57 = lshr i32 %53, 31
  %58 = xor i32 %57, %56
  %59 = xor i32 %55, %56
  %60 = add nuw nsw i32 %59, %58
  %61 = icmp eq i32 %60, 2
  store i8 0, i8* %27, align 1
  %62 = icmp sgt i32 %54, -1
  %63 = xor i1 %62, %61
  %64 = select i1 %63, i64 29, i64 17
  %65 = add i64 %51, %64
  br i1 %63, label %79, label %66

66:                                               ; preds = %50
  %67 = load i32, i32* %48, align 8
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
  store i8 %77, i8* %27, align 1
  br label %79

79:                                               ; preds = %66, %50
  %80 = phi i64 [ %65, %50 ], [ %78, %66 ]
  %81 = load i8, i8* %27, align 1
  %82 = and i8 %81, 1
  %83 = icmp eq i8 %82, 0
  %84 = select i1 %83, i64 11, i64 16
  %85 = add i64 %80, %84
  br i1 %83, label %107, label %86

86:                                               ; preds = %79
  %87 = bitcast i8* %35 to i64*
  %88 = load i64, i64* %87, align 8
  %89 = sext i32 %52 to i64
  %90 = shl nsw i64 %89, 3
  %91 = add i64 %90, %88
  %92 = inttoptr i64 %91 to i8**
  %93 = load i8*, i8** %92, align 8
  %94 = add i64 %85, 17
  %95 = bitcast %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4 to i64*
  store i64 %94, i64* %95, align 8
  %96 = call i64 @atoi(i8* %93)
  %97 = load i32, i32* %49, align 4
  %98 = add i32 %97, -1
  %99 = sext i32 %98 to i64
  %100 = ptrtoint i8* %33 to i64
  %101 = add i64 %99, %100
  %102 = trunc i64 %96 to i8
  %103 = inttoptr i64 %101 to i8*
  store i8 %102, i8* %103, align 1
  %104 = load i32, i32* %49, align 4
  %105 = add i32 %104, 1
  store i32 %105, i32* %49, align 4
  %106 = add i64 %85, -45
  br label %50

107:                                              ; preds = %79
  %108 = add i64 %85, 58
  %109 = bitcast %sub_400520__Ai_S_Sb_S_Sbi_B_0.frame_type_part0* %4 to i64*
  store i64 %108, i64* %109, align 8
  %110 = call i8* @xor_swap(i8* nonnull %33)
  %111 = load i8, i8* %33, align 1
  %112 = zext i8 %111 to i32
  ret i32 %112
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_64(%struct.Memory*, i64, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_32(%struct.Memory*, i64, i32) local_unnamed_addr #1

; Function Attrs: readnone
declare i8** @__anvill_type_hint_S_Sb(i64) local_unnamed_addr #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local zeroext i16 @__remill_read_memory_16(%struct.Memory*, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_16(%struct.Memory*, i64, i16 zeroext) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local zeroext i8 @__remill_read_memory_8(%struct.Memory*, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local %struct.Memory* @__remill_write_memory_8(%struct.Memory*, i64, i8 zeroext) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i32 @__remill_read_memory_32(%struct.Memory*, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(%struct.Memory*, i64) local_unnamed_addr #1

; Function Attrs: readnone
declare i8* @__anvill_type_hint_Sb(i64) local_unnamed_addr #2

; Function Attrs: noinline
define i64 @atoi(i8* %0) #0 {
  %2 = ptrtoint i8* %0 to i64
  %3 = shl i64 %2, 32
  %sext = ashr exact i64 %3, 32
  %4 = and i64 %sext, -16777216
  %5 = getelementptr i8, i8* inttoptr (i64 16777212 to i8*), i64 %4
  %6 = getelementptr i8, i8* %5, i64 -16711681
  %7 = and i64 %2, 16711680
  %8 = getelementptr i8, i8* %6, i64 %7
  %9 = getelementptr i8, i8* %8, i64 -65281
  %10 = and i64 %2, 65280
  %11 = getelementptr i8, i8* %9, i64 %10
  %12 = getelementptr i8, i8* %11, i64 -256
  %13 = and i64 %2, 255
  %14 = getelementptr i8, i8* %12, i64 %13
  %15 = load i8, i8* %14, align 1
  %16 = add i8 %15, -48
  %17 = zext i8 %16 to i64
  ret i64 %17
}

; Function Attrs: readnone
declare i16* @__anvill_type_hint_Sh(i64) local_unnamed_addr #2

; Function Attrs: noinline
define i8* @xor_swap(i8* %0) #0 {
  %2 = ptrtoint i8* %0 to i64
  %3 = shl i64 %2, 32
  %sext = ashr exact i64 %3, 32
  %4 = and i64 %sext, -16777216
  %5 = getelementptr i8, i8* inttoptr (i64 16777212 to i8*), i64 %4
  %6 = getelementptr i8, i8* %5, i64 -16711681
  %7 = and i64 %2, 16711680
  %8 = getelementptr i8, i8* %6, i64 %7
  %9 = getelementptr i8, i8* %8, i64 -65281
  %10 = and i64 %2, 65280
  %11 = getelementptr i8, i8* %9, i64 %10
  %12 = getelementptr i8, i8* %11, i64 -256
  %13 = and i64 %2, 255
  %14 = getelementptr i8, i8* %12, i64 %13
  %15 = load i8, i8* %14, align 1
  %16 = getelementptr i8, i8* %14, i64 1
  %17 = load i8, i8* %16, align 1
  %18 = xor i8 %17, %15
  store i8 %18, i8* %14, align 1
  store i8 %15, i8* %16, align 1
  store i8 %17, i8* %14, align 1
  ret i8* %14
}

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local %struct.Memory* @__remill_function_return(%struct.State* nonnull align 1, i64, %struct.Memory*) local_unnamed_addr #3

; Function Attrs: noinline
declare x86_64_sysvcc i32 @__libc_start_main(i32 (i32, i8**, i8**)*, i32, i8**, i32 (i32, i8**, i8**)*, i32 ()*, i32 ()*, i8*) #0

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { readnone }
attributes #3 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
