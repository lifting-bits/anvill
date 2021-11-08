; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"
target triple = "i386-pc-linux-gnu-elf"

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
%struct.Reg = type { %union.anon.1, i32 }
%union.anon.1 = type { i32 }
%struct.GPR = type { i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg }
%struct.X87Stack = type { [8 x %struct.anon.3] }
%struct.anon.3 = type { [6 x i8], %struct.float80_t }
%struct.float80_t = type { [10 x i8] }
%struct.MMX = type { [8 x %struct.anon.4] }
%struct.anon.4 = type { i64, %union.vec64_t }
%union.vec64_t = type { %struct.uint64v1_t }
%struct.uint64v1_t = type { [1 x i64] }
%struct.FPUStatusFlags = type { i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, [4 x i8] }
%union.anon = type { i64 }
%union.FPU = type { %struct.anon.13 }
%struct.anon.13 = type { %struct.FpuFXSAVE, [96 x i8] }
%struct.FpuFXSAVE = type { %union.SegmentSelector, %union.SegmentSelector, %union.FPUAbridgedTagWord, i8, i16, i32, %union.SegmentSelector, i16, i32, %union.SegmentSelector, i16, %union.anon.1, %union.anon.1, [8 x %struct.FPUStackElem], [16 x %union.vec128_t] }
%union.FPUAbridgedTagWord = type { i8 }
%struct.FPUStackElem = type { %union.anon.11, [6 x i8] }
%union.anon.11 = type { %struct.float80_t }
%union.vec128_t = type { %struct.uint128v1_t }
%struct.uint128v1_t = type { [1 x i128] }
%struct.SegmentCaches = type { %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow, %struct.SegmentShadow }
%struct.SegmentShadow = type { %union.anon, i32, i32 }

@var_835a000_i = global i32 0
@var_83632f0_b = external global i8
@__anvill_reg_EBX = internal local_unnamed_addr global i32 0
@__anvill_reg_ECX = internal local_unnamed_addr global i32 0
@__anvill_reg_EDX = internal local_unnamed_addr global i32 0
@__anvill_reg_ESI = internal local_unnamed_addr global i32 0
@__anvill_reg_EDI = internal local_unnamed_addr global i32 0
@__anvill_reg_EBP = internal local_unnamed_addr global i32 0
@__anvill_reg_XMM0 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM1 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM2 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM3 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM4 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM5 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM6 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_reg_XMM7 = internal local_unnamed_addr global [16 x i8] zeroinitializer
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@__anvill_pc = internal global i8 0
@llvm.compiler.used = appending global [6 x i8*] [i8* bitcast (i32 ()* @sub_804a04a__Avi_B_0 to i8*), i8* bitcast (i32 ()* @sub_804ec5e__Avi_B_0 to i8*), i8* bitcast (i8* (i8*, i32, i8*, i32*)* @sub_823ff60__A_Sbi_Sb_Si_Sb_B_0 to i8*), i8* bitcast (i32 (i8*, i32, i8*, i32)* @sub_8240110__A_Sbi_Sbii_B_0 to i8*), i8* bitcast (i32* @var_835a000_i to i8*), i8* @var_83632f0_b], section "llvm.metadata"

; Function Attrs: noinline
declare i8* @sub_823ff60__A_Sbi_Sb_Si_Sb_B_0(i8*, i32, i8*, i32*) #0

; Function Attrs: noinline
declare i32 @sub_804a04a__Avi_B_0() #0

; Function Attrs: noinline
declare i32 @sub_804ec5e__Avi_B_0() #0

; Function Attrs: noinline
define i32 @sub_8240110__A_Sbi_Sbii_B_0(i8* %0, i32 %1, i8* %2, i32 %3) #0 {
  %5 = load i32, i32* @__anvill_reg_EBX, align 4
  %6 = load i32, i32* @__anvill_reg_ECX, align 4
  %7 = load i32, i32* @__anvill_reg_EDX, align 4
  %8 = load i32, i32* @__anvill_reg_ESI, align 4
  %9 = load i32, i32* @__anvill_reg_EDI, align 4
  %10 = load i32, i32* @__anvill_reg_EBP, align 4
  store i32 ptrtoint (i8* @__anvill_ra to i32), i32* bitcast (i8* @__anvill_sp to i32*), align 4
  %11 = ptrtoint i8* %0 to i32
  store i32 %11, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 4) to i32*), align 4
  store i32 %1, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 8) to i32*), align 4
  %12 = ptrtoint i8* %2 to i32
  store i32 %12, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 12) to i32*), align 4
  store i32 %3, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16) to i32*), align 4
  store i32 %10, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -4) to i32*), align 4
  store i32 %9, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -8) to i32*), align 4
  store i32 %8, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -12) to i32*), align 4
  store i32 136577306, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -16) to i32*), align 4
  %13 = call i32 @sub_804ec5e__Avi_B_0()
  store i32 %5, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -16) to i32*), align 4
  store i32 %7, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -316) to i32*), align 4
  %14 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 4) to i32*), align 4
  store i32 %6, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -308) to i32*), align 4
  store i32 137732096, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -312) to i32*), align 4
  store i32 %14, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -284) to i32*), align 4
  %.not = icmp ult i32 %13, %7
  br i1 %.not, label %18, label %15

15:                                               ; preds = %4
  %16 = load i32, i32* bitcast (i8* @__anvill_sp to i32*), align 4
  %17 = call %struct.Memory* @__remill_function_return(%struct.State* undef, i32 %16, %struct.Memory* null)
  br label %964

18:                                               ; preds = %4
  store i32 137769712, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -304) to i32*), align 4
  br label %19

19:                                               ; preds = %324, %18
  %.sroa.892.0 = phi i32 [ %13, %18 ], [ %.sroa.892.4, %324 ]
  %.sroa.1272.0 = phi i32 [ 1, %18 ], [ %.sroa.1272.1, %324 ]
  %20 = phi i32 [ 136577368, %18 ], [ %328, %324 ]
  %21 = inttoptr i32 %.sroa.892.0 to i8*
  %22 = load i8, i8* %21, align 1
  %23 = zext i8 %22 to i32
  %24 = add i8 %22, -3
  store i32 %23, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -320) to i32*), align 4
  %25 = icmp ult i8 %24, -18
  %26 = icmp eq i8 %22, -15
  %27 = or i1 %26, %25
  %28 = select i1 %27, i32 24, i32 -2054395
  %29 = add i32 %20, %28
  %30 = add i32 %29, 9
  br i1 %27, label %31, label %41

31:                                               ; preds = %19
  %32 = add i32 %.sroa.892.0, 1
  %33 = zext i8 %24 to i32
  %34 = shl nuw nsw i32 %33, 2
  %35 = add nuw nsw i32 %34, 136967784
  %36 = inttoptr i32 %35 to i32*
  %37 = load i32, i32* %36, align 4
  %38 = add i32 %37, 137732096
  %39 = call i32 (i32, ...) @__anvill_complete_switch(i32 %38, i32 134522973, i32 136577416, i32 136577536, i32 136577601, i32 136577616, i32 136577680, i32 136577696, i32 136577752, i32 136577805, i32 136577818, i32 136577855, i32 136577893, i32 136577926, i32 136577948, i32 136577966, i32 136577987, i32 136578001, i32 136578015, i32 136578029, i32 136578086, i32 136578124, i32 136578221, i32 136578306, i32 136578351, i32 136578487, i32 136578552)
  %40 = add i32 %37, 137732105
  switch i32 %39, label %48 [
    i32 0, label %41
    i32 1, label %49
    i32 2, label %51
    i32 3, label %56
    i32 4, label %61
    i32 5, label %75
    i32 6, label %78
    i32 7, label %91
    i32 8, label %95
    i32 9, label %102
    i32 10, label %106
    i32 11, label %119
    i32 12, label %133
    i32 13, label %146
    i32 14, label %150
    i32 15, label %154
    i32 16, label %160
    i32 17, label %166
    i32 18, label %172
    i32 19, label %185
    i32 20, label %198
    i32 21, label %204
    i32 22, label %206
    i32 23, label %769
    i32 24, label %886
    i32 25, label %208
  ]

41:                                               ; preds = %962, %955, %641, %550, %542, %381, %373, %31, %19
  %42 = phi i32 [ %30, %19 ], [ %642, %641 ], [ %963, %962 ], [ %956, %955 ], [ %549, %542 ], [ %558, %550 ], [ %380, %373 ], [ %398, %381 ], [ %40, %31 ]
  store i32 %42, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -336) to i32*), align 4
  %43 = call i32 @sub_804a04a__Avi_B_0()
  br label %44

44:                                               ; preds = %869, %825, %732, %699, %360, %329, %304, %287, %242, %172, %150, %146, %133, %119, %106, %102, %91, %78, %61, %41
  %45 = phi i32 [ %42, %41 ], [ %332, %329 ], [ %317, %304 ], [ %838, %825 ], [ %877, %869 ], [ %711, %699 ], [ %740, %732 ], [ %184, %172 ], [ %153, %150 ], [ %149, %146 ], [ %145, %133 ], [ %132, %119 ], [ %118, %106 ], [ %105, %102 ], [ %94, %91 ], [ %90, %78 ], [ %74, %61 ], [ %368, %360 ], [ %256, %242 ], [ %295, %287 ]
  %46 = add i32 %45, 9
  store i32 %46, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -336) to i32*), align 4
  %47 = call i32 @sub_804a04a__Avi_B_0()
  unreachable

48:                                               ; preds = %31
  unreachable

49:                                               ; preds = %31
  %50 = add i32 %37, 137732104
  br label %210

51:                                               ; preds = %31
  %52 = inttoptr i32 %32 to i32*
  %53 = load i32, i32* %52, align 4
  %54 = add i32 %.sroa.892.0, 5
  %55 = add i32 %37, 137732112
  br label %304

56:                                               ; preds = %31
  %57 = inttoptr i32 %32 to i32*
  %58 = load i32, i32* %57, align 4
  %59 = add i32 %.sroa.892.0, 9
  %60 = add i32 %37, 137732047
  br label %304

61:                                               ; preds = %31
  %62 = add nsw i32 %23, -80
  %63 = add nsw i32 %23, -97
  %64 = icmp ne i32 %63, 0
  %65 = lshr i32 %63, 31
  %66 = lshr i32 %62, 31
  %67 = xor i32 %65, %66
  %68 = add nuw nsw i32 %67, %66
  %69 = icmp eq i32 %68, 2
  %70 = icmp ugt i8 %22, 96
  %71 = xor i1 %70, %69
  %72 = and i1 %71, %64
  %73 = select i1 %72, i32 -2054634, i32 16
  %74 = add i32 %73, %38
  br i1 %72, label %44, label %340

75:                                               ; preds = %31
  %76 = add nsw i32 %23, -48
  %77 = add i32 %37, 137731968
  br label %304

78:                                               ; preds = %31
  %79 = add i32 %.sroa.1272.0, -1
  %80 = icmp eq i32 %79, 0
  %81 = lshr i32 %79, 31
  %82 = lshr i32 %.sroa.1272.0, 31
  %83 = xor i32 %81, %82
  %84 = add nuw nsw i32 %83, %82
  %85 = icmp eq i32 %84, 2
  %86 = icmp slt i32 %79, 0
  %87 = xor i1 %86, %85
  %88 = or i1 %80, %87
  %89 = select i1 %88, i32 -2054714, i32 9
  %90 = add i32 %89, %38
  br i1 %88, label %44, label %373

91:                                               ; preds = %31
  %92 = icmp eq i32 %.sroa.1272.0, 0
  %93 = select i1 %92, i32 -2054770, i32 8
  %94 = add i32 %93, %38
  br i1 %92, label %44, label %529

95:                                               ; preds = %31
  %96 = inttoptr i32 %32 to i16*
  %97 = load i16, i16* %96, align 2
  %98 = sext i16 %97 to i32
  %99 = add i32 %.sroa.892.0, 3
  %100 = add i32 %99, %98
  %101 = add i32 %37, 137731859
  br label %324

102:                                              ; preds = %31
  %103 = icmp eq i32 %.sroa.1272.0, 0
  %104 = select i1 %103, i32 -2054836, i32 8
  %105 = add i32 %104, %38
  br i1 %103, label %44, label %575

106:                                              ; preds = %31
  %107 = add i32 %.sroa.1272.0, -1
  %108 = icmp eq i32 %107, 0
  %109 = lshr i32 %107, 31
  %110 = lshr i32 %.sroa.1272.0, 31
  %111 = xor i32 %109, %110
  %112 = add nuw nsw i32 %111, %110
  %113 = icmp eq i32 %112, 2
  %114 = icmp slt i32 %107, 0
  %115 = xor i1 %114, %113
  %116 = or i1 %108, %115
  %117 = select i1 %116, i32 -2054873, i32 9
  %118 = add i32 %117, %38
  br i1 %116, label %44, label %593

119:                                              ; preds = %31
  %120 = inttoptr i32 %32 to i8*
  %121 = load i8, i8* %120, align 1
  %122 = zext i8 %121 to i32
  %123 = add i32 %.sroa.1272.0, -1
  %124 = sub i32 %122, %123
  %125 = lshr i32 %124, 31
  %126 = lshr i32 %123, 31
  %127 = add nuw nsw i32 %125, %126
  %128 = icmp eq i32 %127, 2
  %129 = icmp sgt i32 %124, -1
  %130 = xor i1 %129, %128
  %131 = select i1 %130, i32 -2054911, i32 18
  %132 = add i32 %131, %38
  br i1 %130, label %44, label %603

133:                                              ; preds = %31
  %134 = add i32 %.sroa.1272.0, -1
  %135 = icmp eq i32 %134, 0
  %136 = lshr i32 %134, 31
  %137 = lshr i32 %.sroa.1272.0, 31
  %138 = xor i32 %136, %137
  %139 = add nuw nsw i32 %138, %137
  %140 = icmp eq i32 %139, 2
  %141 = icmp slt i32 %134, 0
  %142 = xor i1 %141, %140
  %143 = or i1 %135, %142
  %144 = select i1 %143, i32 -2054944, i32 9
  %145 = add i32 %144, %38
  br i1 %143, label %44, label %611

146:                                              ; preds = %31
  %147 = icmp eq i32 %.sroa.1272.0, 0
  %148 = select i1 %147, i32 -2054966, i32 8
  %149 = add i32 %148, %38
  br i1 %147, label %44, label %617

150:                                              ; preds = %31
  %151 = icmp eq i32 %.sroa.1272.0, 0
  %152 = select i1 %151, i32 -2054984, i32 8
  %153 = add i32 %152, %38
  br i1 %151, label %44, label %620

154:                                              ; preds = %31
  %155 = inttoptr i32 %32 to i16*
  %156 = load i16, i16* %155, align 2
  %157 = sext i16 %156 to i32
  %158 = add i32 %.sroa.892.0, 3
  %159 = add i32 %37, 137731661
  br label %304

160:                                              ; preds = %31
  %161 = inttoptr i32 %32 to i16*
  %162 = load i16, i16* %161, align 2
  %163 = zext i16 %162 to i32
  %164 = add i32 %.sroa.892.0, 3
  %165 = add i32 %37, 137731647
  br label %304

166:                                              ; preds = %31
  %167 = inttoptr i32 %32 to i8*
  %168 = load i8, i8* %167, align 1
  %169 = sext i8 %168 to i32
  %170 = add i32 %.sroa.892.0, 2
  %171 = add i32 %37, 137731633
  br label %304

172:                                              ; preds = %31
  %173 = add i32 %.sroa.1272.0, -2
  %174 = icmp eq i32 %173, 0
  %175 = lshr i32 %173, 31
  %176 = lshr i32 %.sroa.1272.0, 31
  %177 = xor i32 %175, %176
  %178 = add nuw nsw i32 %177, %176
  %179 = icmp eq i32 %178, 2
  %180 = icmp slt i32 %173, 0
  %181 = xor i1 %180, %179
  %182 = or i1 %174, %181
  %183 = select i1 %182, i32 -2055047, i32 9
  %184 = add i32 %183, %38
  br i1 %182, label %44, label %626

185:                                              ; preds = %31
  store i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -288), i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -348) to i32*), align 4
  %186 = add i32 %37, 137732122
  store i32 %186, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -352) to i32*), align 4
  %187 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -348) to i32*), align 4
  %188 = inttoptr i32 %187 to i8*
  %189 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -344) to i32*), align 4
  %190 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -340) to i32*), align 4
  %191 = inttoptr i32 %190 to i8*
  %192 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -336) to i32*), align 4
  %193 = inttoptr i32 %192 to i32*
  %194 = call i8* @sub_823ff60__A_Sbi_Sb_Si_Sb_B_0(i8* %188, i32 %189, i8* %191, i32* %193)
  %195 = ptrtoint i8* %194 to i32
  %196 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -288) to i32*), align 4
  %197 = add i32 %37, 137731562
  br label %304

198:                                              ; preds = %31
  %199 = inttoptr i32 %32 to i8*
  %200 = load i8, i8* %199, align 1
  %201 = zext i8 %200 to i32
  %202 = add i32 %.sroa.892.0, 2
  %203 = add i32 %37, 137731524
  br label %304

204:                                              ; preds = %31
  %205 = add i32 %37, 137732107
  br label %677

206:                                              ; preds = %31
  %207 = add i32 %37, 137732110
  br label %745

208:                                              ; preds = %31
  %209 = add i32 %37, 137731112
  br label %324

210:                                              ; preds = %224, %49
  %.sroa.1109.0 = phi i32 [ 0, %49 ], [ %226, %224 ]
  %.sroa.1225.0 = phi i32 [ 0, %49 ], [ %227, %224 ]
  %.sroa.1330.0 = phi i32 [ %32, %49 ], [ %225, %224 ]
  %211 = phi i32 [ %50, %49 ], [ %230, %224 ]
  %212 = inttoptr i32 %.sroa.1330.0 to i8*
  %213 = load i8, i8* %212, align 1
  %214 = and i8 %213, 127
  %215 = zext i8 %214 to i32
  %216 = and i32 %.sroa.1109.0, 31
  %217 = shl i32 %215, 1
  switch i32 %216, label %218 [
    i32 0, label %224
    i32 1, label %222
  ]

218:                                              ; preds = %210
  %219 = add nsw i32 %216, -1
  %220 = shl i32 %215, %219
  %221 = shl i32 %220, 1
  br label %222

222:                                              ; preds = %210, %218
  %223 = phi i32 [ %221, %218 ], [ %217, %210 ]
  br label %224

224:                                              ; preds = %210, %222
  %.sroa.892.1 = phi i32 [ %223, %222 ], [ %215, %210 ]
  %225 = add i32 %.sroa.1330.0, 1
  %226 = add i32 %.sroa.1109.0, 7
  %227 = or i32 %.sroa.892.1, %.sroa.1225.0
  %228 = add i32 %211, 23
  %229 = icmp sgt i8 %213, -1
  %230 = select i1 %229, i32 %228, i32 %211
  %231 = icmp slt i8 %213, 0
  br i1 %231, label %210, label %232

232:                                              ; preds = %224
  %233 = icmp ugt i32 %226, 31
  %234 = select i1 %233, i32 23, i32 9
  %235 = add i32 %230, %234
  br i1 %233, label %242, label %236

236:                                              ; preds = %232
  %237 = lshr i8 %213, 6
  %238 = and i8 %237, 1
  %.not190 = icmp eq i8 %238, 0
  %239 = select i1 %.not190, i32 14, i32 5
  %240 = add i32 %235, %239
  %241 = icmp eq i8 %238, 0
  br i1 %241, label %242, label %257

242:                                              ; preds = %264, %236, %232
  %.sroa.1225.1 = phi i32 [ %227, %232 ], [ %227, %236 ], [ %266, %264 ]
  %243 = phi i32 [ %235, %232 ], [ %240, %236 ], [ %265, %264 ]
  %244 = add nsw i32 %23, -112
  %245 = add nsw i32 %23, -129
  %246 = icmp ne i32 %245, 0
  %247 = lshr i32 %245, 31
  %248 = lshr i32 %244, 31
  %249 = xor i32 %247, %248
  %250 = add nuw nsw i32 %249, %248
  %251 = icmp eq i32 %250, 2
  %252 = icmp ugt i8 %22, -128
  %253 = xor i1 %252, %251
  %254 = and i1 %253, %246
  %255 = select i1 %254, i32 -2054488, i32 16
  %256 = add i32 %243, %255
  br i1 %254, label %44, label %267

257:                                              ; preds = %236
  %258 = and i32 %226, 31
  switch i32 %258, label %259 [
    i32 0, label %264
    i32 1, label %262
  ]

259:                                              ; preds = %257
  %260 = add nsw i32 %258, -1
  %261 = shl i32 -2, %260
  br label %262

262:                                              ; preds = %257, %259
  %263 = phi i32 [ %261, %259 ], [ -2, %257 ]
  br label %264

264:                                              ; preds = %257, %262
  %.sroa.892.2 = phi i32 [ %263, %262 ], [ -1, %257 ]
  %265 = add i32 %240, 9
  %266 = or i32 %.sroa.892.2, %227
  br label %242

267:                                              ; preds = %242
  %268 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -308) to i32*), align 4
  %269 = shl nsw i32 %244, 2
  %270 = add i32 %269, %268
  %271 = inttoptr i32 %270 to i32*
  %272 = load i32, i32* %271, align 4
  %273 = add i32 %268, 99
  %274 = inttoptr i32 %273 to i8*
  %275 = load i8, i8* %274, align 1
  %276 = and i8 %275, 64
  %.not9 = icmp eq i8 %276, 0
  %277 = select i1 %.not9, i32 20, i32 13
  %278 = add i32 %256, %277
  br i1 %.not9, label %287, label %279

279:                                              ; preds = %267
  %280 = add i32 %268, 108
  %281 = add i32 %280, %244
  %282 = inttoptr i32 %281 to i8*
  %283 = load i8, i8* %282, align 1
  %.not10 = icmp eq i8 %283, 0
  %284 = select i1 %.not10, i32 7, i32 28
  %285 = add i32 %278, %284
  %286 = add i32 %285, 25
  br i1 %.not10, label %287, label %296

287:                                              ; preds = %279, %267
  %288 = phi i32 [ %278, %267 ], [ %285, %279 ]
  %289 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -304) to i32*), align 4
  %290 = add i32 %244, %289
  %291 = inttoptr i32 %290 to i8*
  %292 = load i8, i8* %291, align 1
  %293 = icmp eq i8 %292, 4
  %294 = select i1 %293, i32 19, i32 -2054524
  %295 = add i32 %288, %294
  br i1 %293, label %299, label %44

296:                                              ; preds = %299, %279
  %.sroa.989.0 = phi i32 [ %302, %299 ], [ %272, %279 ]
  %297 = phi i32 [ %303, %299 ], [ %286, %279 ]
  %298 = add i32 %.sroa.1225.1, %.sroa.989.0
  br label %304

299:                                              ; preds = %287
  %300 = inttoptr i32 %272 to i32*
  %301 = add i32 %295, 2
  %302 = load i32, i32* %300, align 4
  %303 = add i32 %301, 25
  br label %296

304:                                              ; preds = %724, %741, %352, %369, %957, %952, %927, %914, %908, %878, %767, %672, %655, %620, %611, %603, %569, %566, %563, %560, %525, %522, %519, %515, %512, %499, %496, %481, %468, %464, %461, %459, %449, %439, %428, %415, %400, %296, %198, %185, %166, %160, %154, %75, %56, %51
  %.sroa.892.3 = phi i32 [ %901, %908 ], [ %901, %914 ], [ %901, %927 ], [ %808, %878 ], [ %760, %767 ], [ %202, %198 ], [ %195, %185 ], [ %170, %166 ], [ %164, %160 ], [ %158, %154 ], [ %32, %620 ], [ %32, %611 ], [ %604, %603 ], [ %644, %655 ], [ %644, %672 ], [ %644, %957 ], [ %945, %952 ], [ %32, %569 ], [ %32, %566 ], [ %32, %563 ], [ %32, %560 ], [ %32, %525 ], [ %32, %522 ], [ %32, %519 ], [ %32, %515 ], [ %32, %512 ], [ %32, %499 ], [ %32, %496 ], [ %32, %481 ], [ %32, %468 ], [ %32, %464 ], [ %32, %461 ], [ %32, %459 ], [ %32, %449 ], [ %32, %439 ], [ %32, %428 ], [ %32, %415 ], [ %32, %400 ], [ %32, %75 ], [ %59, %56 ], [ %54, %51 ], [ %225, %296 ], [ %32, %369 ], [ %32, %352 ], [ %692, %741 ], [ %692, %724 ]
  %.sroa.989.1 = phi i32 [ %903, %908 ], [ %903, %914 ], [ %928, %927 ], [ %880, %878 ], [ %762, %767 ], [ %201, %198 ], [ %196, %185 ], [ %169, %166 ], [ %163, %160 ], [ %157, %154 ], [ %624, %620 ], [ %615, %611 ], [ %609, %603 ], [ %658, %655 ], [ %675, %672 ], [ %960, %957 ], [ %953, %952 ], [ %571, %569 ], [ %567, %566 ], [ %564, %563 ], [ %561, %560 ], [ %527, %525 ], [ %523, %522 ], [ %520, %519 ], [ %517, %515 ], [ %513, %512 ], [ %510, %499 ], [ %497, %496 ], [ %494, %481 ], [ %479, %468 ], [ %466, %464 ], [ %462, %461 ], [ %.sroa.989.5, %459 ], [ %.sroa.989.4, %449 ], [ %.sroa.989.3, %439 ], [ %429, %428 ], [ %426, %415 ], [ %413, %400 ], [ %76, %75 ], [ %58, %56 ], [ %53, %51 ], [ %298, %296 ], [ %371, %369 ], [ %345, %352 ], [ %743, %741 ], [ %717, %724 ]
  %.sroa.1225.2 = phi i32 [ %.sroa.1272.0, %908 ], [ %.sroa.1272.0, %914 ], [ %.sroa.1272.0, %927 ], [ %.sroa.1272.0, %878 ], [ %.sroa.1272.0, %767 ], [ %.sroa.1272.0, %198 ], [ %.sroa.1272.0, %185 ], [ %.sroa.1272.0, %166 ], [ %.sroa.1272.0, %160 ], [ %.sroa.1272.0, %154 ], [ %.sroa.1272.0, %620 ], [ %.sroa.1272.0, %611 ], [ %.sroa.1272.0, %603 ], [ %530, %655 ], [ %530, %672 ], [ %530, %957 ], [ %530, %952 ], [ %530, %569 ], [ %530, %566 ], [ %530, %563 ], [ %530, %560 ], [ %382, %525 ], [ %382, %522 ], [ %382, %519 ], [ %382, %515 ], [ %382, %512 ], [ %382, %499 ], [ %382, %496 ], [ %382, %481 ], [ %382, %468 ], [ %382, %464 ], [ %382, %461 ], [ %382, %459 ], [ %382, %449 ], [ %382, %439 ], [ %382, %428 ], [ %382, %415 ], [ %382, %400 ], [ %.sroa.1272.0, %75 ], [ %.sroa.1272.0, %56 ], [ %.sroa.1272.0, %51 ], [ %.sroa.1272.0, %296 ], [ %.sroa.1272.0, %369 ], [ %.sroa.1272.0, %352 ], [ %.sroa.1272.0, %741 ], [ %.sroa.1272.0, %724 ]
  %305 = phi i32 [ %913, %908 ], [ %918, %914 ], [ %929, %927 ], [ %879, %878 ], [ %768, %767 ], [ %203, %198 ], [ %197, %185 ], [ %171, %166 ], [ %165, %160 ], [ %159, %154 ], [ %625, %620 ], [ %616, %611 ], [ %610, %603 ], [ %656, %655 ], [ %676, %672 ], [ %961, %957 ], [ %954, %952 ], [ %572, %569 ], [ %568, %566 ], [ %565, %563 ], [ %562, %560 ], [ %528, %525 ], [ %524, %522 ], [ %521, %519 ], [ %518, %515 ], [ %514, %512 ], [ %511, %499 ], [ %498, %496 ], [ %495, %481 ], [ %480, %468 ], [ %467, %464 ], [ %463, %461 ], [ %460, %459 ], [ %450, %449 ], [ %440, %439 ], [ %430, %428 ], [ %427, %415 ], [ %414, %400 ], [ %77, %75 ], [ %60, %56 ], [ %55, %51 ], [ %297, %296 ], [ %372, %369 ], [ %359, %352 ], [ %744, %741 ], [ %731, %724 ]
  %306 = add i32 %.sroa.1225.2, -63
  %307 = icmp ne i32 %306, 0
  %308 = lshr i32 %306, 31
  %309 = lshr i32 %.sroa.1225.2, 31
  %310 = xor i32 %308, %309
  %311 = add nuw nsw i32 %310, %309
  %312 = icmp eq i32 %311, 2
  %313 = icmp sgt i32 %306, -1
  %314 = xor i1 %313, %312
  %315 = and i1 %314, %307
  %316 = select i1 %315, i32 -2054570, i32 9
  %317 = add i32 %305, %316
  br i1 %315, label %44, label %318

318:                                              ; preds = %304
  %319 = shl i32 %.sroa.1225.2, 2
  %320 = add i32 %319, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -284)
  %321 = inttoptr i32 %320 to i32*
  store i32 %.sroa.989.1, i32* %321, align 4
  %322 = add i32 %317, 7
  %323 = add i32 %.sroa.1225.2, 1
  br label %324

324:                                              ; preds = %626, %617, %593, %587, %585, %318, %208, %95
  %.sroa.892.4 = phi i32 [ %32, %208 ], [ %.sroa.892.3, %318 ], [ %32, %626 ], [ %32, %617 ], [ %32, %593 ], [ %577, %585 ], [ %591, %587 ], [ %100, %95 ]
  %.sroa.1272.1 = phi i32 [ %.sroa.1272.0, %208 ], [ %323, %318 ], [ %.sroa.1272.0, %626 ], [ %618, %617 ], [ %.sroa.1272.0, %593 ], [ %576, %585 ], [ %576, %587 ], [ %.sroa.1272.0, %95 ]
  %325 = phi i32 [ %209, %208 ], [ %322, %318 ], [ %640, %626 ], [ %619, %617 ], [ %602, %593 ], [ %586, %585 ], [ %592, %587 ], [ %101, %95 ]
  %326 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -316) to i32*), align 4
  %.not3 = icmp ugt i32 %326, %.sroa.892.4
  %327 = select i1 %.not3, i32 -200, i32 10
  %328 = add i32 %325, %327
  br i1 %.not3, label %19, label %329

329:                                              ; preds = %324
  %330 = icmp eq i32 %.sroa.1272.1, 0
  %331 = select i1 %330, i32 -2054596, i32 8
  %332 = add i32 %328, %331
  br i1 %330, label %44, label %333

333:                                              ; preds = %329
  %334 = shl i32 %.sroa.1272.1, 2
  %335 = add i32 %334, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -288)
  %336 = inttoptr i32 %335 to i32*
  %337 = load i32, i32* %336, align 4
  %338 = load i32, i32* bitcast (i8* @__anvill_sp to i32*), align 4
  %339 = call %struct.Memory* @__remill_function_return(%struct.State* undef, i32 %338, %struct.Memory* null)
  br label %964

340:                                              ; preds = %61
  %341 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -308) to i32*), align 4
  %342 = shl nsw i32 %62, 2
  %343 = add i32 %342, %341
  %344 = inttoptr i32 %343 to i32*
  %345 = load i32, i32* %344, align 4
  %346 = add i32 %341, 99
  %347 = inttoptr i32 %346 to i8*
  %348 = load i8, i8* %347, align 1
  %349 = and i8 %348, 64
  %.not7 = icmp eq i8 %349, 0
  %350 = select i1 %.not7, i32 20, i32 13
  %351 = add i32 %74, %350
  br i1 %.not7, label %360, label %352

352:                                              ; preds = %340
  %353 = add i32 %341, 108
  %354 = add i32 %353, %62
  %355 = inttoptr i32 %354 to i8*
  %356 = load i8, i8* %355, align 1
  %.not8 = icmp eq i8 %356, 0
  %357 = select i1 %.not8, i32 7, i32 28
  %358 = add i32 %351, %357
  %359 = add i32 %358, -121
  br i1 %.not8, label %360, label %304

360:                                              ; preds = %352, %340
  %361 = phi i32 [ %351, %340 ], [ %358, %352 ]
  %362 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -304) to i32*), align 4
  %363 = add i32 %62, %362
  %364 = inttoptr i32 %363 to i8*
  %365 = load i8, i8* %364, align 1
  %366 = icmp eq i8 %365, 4
  %367 = select i1 %366, i32 19, i32 -2054670
  %368 = add i32 %361, %367
  br i1 %366, label %369, label %44

369:                                              ; preds = %360
  %370 = inttoptr i32 %345 to i32*
  %371 = load i32, i32* %370, align 4
  %372 = add i32 %368, -119
  br label %304

373:                                              ; preds = %78
  %374 = add i8 %22, -26
  %375 = icmp ult i8 %374, 20
  %376 = icmp eq i8 %22, 46
  %377 = or i1 %376, %375
  %378 = select i1 %377, i32 23, i32 -2054732
  %379 = add i32 %90, %378
  %380 = add i32 %379, 9
  br i1 %377, label %381, label %41

381:                                              ; preds = %373
  %382 = add i32 %.sroa.1272.0, -2
  %383 = shl i32 %.sroa.1272.0, 2
  %384 = add i32 %383, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -288)
  %385 = inttoptr i32 %384 to i32*
  %386 = load i32, i32* %385, align 4
  %387 = shl i32 %382, 2
  %388 = add i32 %387, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -284)
  %389 = inttoptr i32 %388 to i32*
  %390 = load i32, i32* %389, align 4
  %391 = zext i8 %374 to i32
  %392 = shl nuw nsw i32 %391, 2
  %393 = add nuw nsw i32 %392, 136968740
  %394 = inttoptr i32 %393 to i32*
  %395 = load i32, i32* %394, align 4
  %396 = add i32 %395, 137732096
  %397 = call i32 (i32, ...) @__anvill_complete_switch(i32 %396, i32 134522973, i32 136578559, i32 136578574, i32 136578589, i32 136578598, i32 136578609, i32 136578620, i32 136578631, i32 136578640, i32 136578655, i32 136578670, i32 136578685, i32 136578694, i32 136578708, i32 136578717, i32 136578732, i32 136578742, i32 136578751)
  %398 = add i32 %395, 137732105
  switch i32 %397, label %399 [
    i32 0, label %41
    i32 1, label %400
    i32 2, label %415
    i32 3, label %428
    i32 4, label %431
    i32 5, label %441
    i32 6, label %451
    i32 7, label %461
    i32 8, label %464
    i32 9, label %468
    i32 10, label %481
    i32 11, label %496
    i32 12, label %499
    i32 13, label %512
    i32 14, label %515
    i32 15, label %519
    i32 16, label %522
    i32 17, label %525
  ]

399:                                              ; preds = %381
  unreachable

400:                                              ; preds = %381
  %401 = sub i32 %390, %386
  %402 = icmp eq i32 %401, 0
  %403 = lshr i32 %401, 31
  %404 = lshr i32 %390, 31
  %405 = lshr i32 %386, 31
  %406 = xor i32 %405, %404
  %407 = xor i32 %403, %404
  %408 = add nuw nsw i32 %407, %406
  %409 = icmp eq i32 %408, 2
  %410 = icmp slt i32 %401, 0
  %411 = xor i1 %410, %409
  %412 = or i1 %402, %411
  %413 = zext i1 %412 to i32
  %414 = add i32 %395, 137731089
  br label %304

415:                                              ; preds = %381
  %416 = sub i32 %390, %386
  %417 = lshr i32 %416, 31
  %418 = lshr i32 %390, 31
  %419 = lshr i32 %386, 31
  %420 = xor i32 %419, %418
  %421 = xor i32 %417, %418
  %422 = add nuw nsw i32 %421, %420
  %423 = icmp eq i32 %422, 2
  %424 = icmp slt i32 %416, 0
  %425 = xor i1 %424, %423
  %426 = zext i1 %425 to i32
  %427 = add i32 %395, 137731074
  br label %304

428:                                              ; preds = %381
  %429 = add i32 %386, %390
  %430 = add i32 %395, 137731059
  br label %304

431:                                              ; preds = %381
  %432 = and i32 %386, 31
  switch i32 %432, label %435 [
    i32 0, label %439
    i32 1, label %433
  ]

433:                                              ; preds = %431
  %434 = shl i32 %390, 1
  br label %439

435:                                              ; preds = %431
  %436 = add nsw i32 %432, -1
  %437 = shl i32 %390, %436
  %438 = shl i32 %437, 1
  br label %439

439:                                              ; preds = %433, %435, %431
  %.sroa.989.3 = phi i32 [ %390, %431 ], [ %434, %433 ], [ %438, %435 ]
  %440 = add i32 %395, 137731050
  br label %304

441:                                              ; preds = %381
  %442 = and i32 %386, 31
  switch i32 %442, label %445 [
    i32 0, label %449
    i32 1, label %443
  ]

443:                                              ; preds = %441
  %444 = lshr i32 %390, 1
  br label %449

445:                                              ; preds = %441
  %446 = add nsw i32 %442, -1
  %447 = lshr i32 %390, %446
  %448 = lshr i32 %447, 1
  br label %449

449:                                              ; preds = %443, %445, %441
  %.sroa.989.4 = phi i32 [ %390, %441 ], [ %448, %445 ], [ %444, %443 ]
  %450 = add i32 %395, 137731039
  br label %304

451:                                              ; preds = %381
  %452 = and i32 %386, 31
  switch i32 %452, label %455 [
    i32 0, label %459
    i32 1, label %453
  ]

453:                                              ; preds = %451
  %454 = ashr i32 %390, 1
  br label %459

455:                                              ; preds = %451
  %456 = add nsw i32 %452, -1
  %457 = ashr i32 %390, %456
  %458 = ashr i32 %457, 1
  br label %459

459:                                              ; preds = %453, %455, %451
  %.sroa.989.5 = phi i32 [ %390, %451 ], [ %454, %453 ], [ %458, %455 ]
  %460 = add i32 %395, 137731028
  br label %304

461:                                              ; preds = %381
  %462 = xor i32 %386, %390
  %463 = add i32 %395, 137731017
  br label %304

464:                                              ; preds = %381
  %465 = icmp eq i32 %390, %386
  %466 = zext i1 %465 to i32
  %467 = add i32 %395, 137731008
  br label %304

468:                                              ; preds = %381
  %469 = sub i32 %390, %386
  %470 = lshr i32 %469, 31
  %471 = lshr i32 %390, 31
  %472 = lshr i32 %386, 31
  %473 = xor i32 %472, %471
  %474 = xor i32 %470, %471
  %475 = add nuw nsw i32 %474, %473
  %476 = icmp eq i32 %475, 2
  %477 = icmp sgt i32 %469, -1
  %478 = xor i1 %477, %476
  %479 = zext i1 %478 to i32
  %480 = add i32 %395, 137730993
  br label %304

481:                                              ; preds = %381
  %482 = sub i32 %390, %386
  %483 = icmp ne i32 %482, 0
  %484 = lshr i32 %482, 31
  %485 = lshr i32 %390, 31
  %486 = lshr i32 %386, 31
  %487 = xor i32 %486, %485
  %488 = xor i32 %484, %485
  %489 = add nuw nsw i32 %488, %487
  %490 = icmp eq i32 %489, 2
  %491 = icmp sgt i32 %482, -1
  %492 = xor i1 %491, %490
  %493 = and i1 %492, %483
  %494 = zext i1 %493 to i32
  %495 = add i32 %395, 137730978
  br label %304

496:                                              ; preds = %381
  %497 = and i32 %386, %390
  %498 = add i32 %395, 137730963
  br label %304

499:                                              ; preds = %381
  %500 = icmp ne i32 %386, 0
  call void @llvm.assume(i1 %500)
  %501 = ashr i32 %390, 31
  %502 = zext i32 %390 to i64
  %503 = zext i32 %501 to i64
  %504 = sext i32 %386 to i64
  %505 = shl nuw i64 %503, 32
  %506 = or i64 %505, %502
  %507 = sdiv i64 %506, %504
  %508 = add i64 %507, 2147483648
  %509 = icmp ult i64 %508, 4294967296
  call void @llvm.assume(i1 %509)
  %510 = trunc i64 %507 to i32
  %511 = add i32 %395, 137730954
  br label %304

512:                                              ; preds = %381
  %513 = sub i32 %390, %386
  %514 = add i32 %395, 137730940
  br label %304

515:                                              ; preds = %381
  %516 = icmp ne i32 %386, 0
  call void @llvm.assume(i1 %516)
  %517 = urem i32 %390, %386
  %518 = add i32 %395, 137730931
  br label %304

519:                                              ; preds = %381
  %520 = mul i32 %386, %390
  %521 = add i32 %395, 137730916
  br label %304

522:                                              ; preds = %381
  %523 = or i32 %386, %390
  %524 = add i32 %395, 137730906
  br label %304

525:                                              ; preds = %381
  %526 = icmp ne i32 %390, %386
  %527 = zext i1 %526 to i32
  %528 = add i32 %395, 137730897
  br label %304

529:                                              ; preds = %91
  %530 = add i32 %.sroa.1272.0, -1
  %531 = shl i32 %530, 2
  %532 = add i32 %531, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -284)
  %533 = inttoptr i32 %532 to i32*
  %534 = load i32, i32* %533, align 4
  %535 = icmp ugt i8 %22, 35
  %536 = select i1 %535, i32 378, i32 16
  %537 = add i32 %94, %536
  br i1 %535, label %538, label %542

538:                                              ; preds = %529
  %539 = icmp eq i8 %22, -108
  %540 = select i1 %539, i32 9, i32 748
  %541 = add i32 %537, %540
  br i1 %539, label %643, label %641

542:                                              ; preds = %529
  %543 = add i8 %22, -6
  %544 = icmp ult i8 %543, 29
  %545 = icmp eq i8 %22, 35
  %546 = or i1 %545, %544
  %547 = select i1 %546, i32 12, i32 -2054803
  %548 = add i32 %537, %547
  %549 = add i32 %548, 9
  br i1 %546, label %550, label %41

550:                                              ; preds = %542
  %551 = zext i8 %543 to i32
  %552 = shl nuw nsw i32 %551, 2
  %553 = add nuw nsw i32 %552, 136968824
  %554 = inttoptr i32 %553 to i32*
  %555 = load i32, i32* %554, align 4
  %556 = add i32 %555, 137732096
  %557 = call i32 (i32, ...) @__anvill_complete_switch(i32 %556, i32 134522973, i32 136578775, i32 136578784, i32 136578793, i32 136578809, i32 136578818)
  %558 = add i32 %555, 137732105
  switch i32 %557, label %559 [
    i32 0, label %41
    i32 1, label %560
    i32 2, label %563
    i32 3, label %566
    i32 4, label %569
    i32 5, label %573
  ]

559:                                              ; preds = %550
  unreachable

560:                                              ; preds = %550
  %561 = xor i32 %534, -1
  %562 = add i32 %555, 137730873
  br label %304

563:                                              ; preds = %550
  %564 = sub i32 0, %534
  %565 = add i32 %555, 137730864
  br label %304

566:                                              ; preds = %550
  %567 = call i32 @llvm.abs.i32(i32 %534, i1 false)
  %568 = add i32 %555, 137730855
  br label %304

569:                                              ; preds = %550
  %570 = inttoptr i32 %534 to i32*
  %571 = load i32, i32* %570, align 4
  %572 = add i32 %555, 137730839
  br label %304

573:                                              ; preds = %550
  %574 = add i32 %555, 137732110
  br label %930

575:                                              ; preds = %102
  %576 = add i32 %.sroa.1272.0, -1
  %577 = add i32 %.sroa.892.0, 3
  %578 = shl i32 %576, 2
  %579 = add i32 %578, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -284)
  %580 = inttoptr i32 %579 to i32*
  %581 = load i32, i32* %580, align 4
  %582 = icmp eq i32 %581, 0
  %583 = select i1 %582, i32 366, i32 18
  %584 = add i32 %105, %583
  br i1 %582, label %585, label %587

585:                                              ; preds = %575
  %586 = add i32 %584, -624
  br label %324

587:                                              ; preds = %575
  %588 = inttoptr i32 %32 to i16*
  %589 = load i16, i16* %588, align 2
  %590 = sext i16 %589 to i32
  %591 = add i32 %577, %590
  %592 = add i32 %584, -276
  br label %324

593:                                              ; preds = %106
  %594 = shl i32 %.sroa.1272.0, 2
  %595 = add i32 %594, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -292)
  %596 = inttoptr i32 %595 to i32*
  %597 = load i32, i32* %596, align 4
  %598 = shl i32 %107, 2
  %599 = add i32 %598, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -284)
  %600 = inttoptr i32 %599 to i32*
  %601 = load i32, i32* %600, align 4
  store i32 %597, i32* %600, align 4
  store i32 %601, i32* %596, align 4
  %602 = add i32 %118, -296
  br label %324

603:                                              ; preds = %119
  %604 = add i32 %.sroa.892.0, 2
  %605 = sub i32 %123, %122
  %606 = shl i32 %605, 2
  %607 = add i32 %606, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -284)
  %608 = inttoptr i32 %607 to i32*
  %609 = load i32, i32* %608, align 4
  %610 = add i32 %132, -359
  br label %304

611:                                              ; preds = %133
  %612 = shl i32 %.sroa.1272.0, 2
  %613 = add i32 %612, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -292)
  %614 = inttoptr i32 %613 to i32*
  %615 = load i32, i32* %614, align 4
  %616 = add i32 %145, -383
  br label %304

617:                                              ; preds = %146
  %618 = add i32 %.sroa.1272.0, -1
  %619 = add i32 %149, -388
  br label %324

620:                                              ; preds = %150
  %621 = shl i32 %.sroa.1272.0, 2
  %622 = add i32 %621, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -288)
  %623 = inttoptr i32 %622 to i32*
  %624 = load i32, i32* %623, align 4
  %625 = add i32 %153, -422
  br label %304

626:                                              ; preds = %172
  %627 = shl i32 %.sroa.1272.0, 2
  %628 = add i32 %627, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -288)
  %629 = inttoptr i32 %628 to i32*
  %630 = load i32, i32* %629, align 4
  %631 = shl i32 %173, 2
  %632 = add i32 %631, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -284)
  %633 = inttoptr i32 %632 to i32*
  %634 = load i32, i32* %633, align 4
  store i32 %630, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -320) to i32*), align 4
  %635 = shl i32 %.sroa.1272.0, 2
  %636 = add i32 %635, add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -296)
  %637 = inttoptr i32 %636 to i32*
  %638 = load i32, i32* %637, align 4
  store i32 %634, i32* %629, align 4
  %639 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -320) to i32*), align 4
  store i32 %638, i32* %633, align 4
  store i32 %639, i32* %637, align 4
  %640 = add i32 %184, -470
  br label %324

641:                                              ; preds = %538
  %642 = add i32 %541, -2055904
  br label %41

643:                                              ; preds = %538
  %644 = add i32 %.sroa.892.0, 2
  %645 = inttoptr i32 %32 to i8*
  %646 = load i8, i8* %645, align 1
  %647 = icmp eq i8 %646, 4
  %648 = select i1 %647, i32 619, i32 15
  %649 = add i32 %541, %648
  %650 = add i32 %649, -1214
  br i1 %647, label %655, label %651

651:                                              ; preds = %643
  %652 = icmp ugt i8 %646, 4
  %653 = select i1 %652, i32 715, i32 6
  %654 = add i32 %649, %653
  br i1 %652, label %659, label %664

655:                                              ; preds = %659, %643
  %656 = phi i32 [ %650, %643 ], [ %663, %659 ]
  %657 = inttoptr i32 %534 to i32*
  %658 = load i32, i32* %657, align 4
  br label %304

659:                                              ; preds = %651
  %660 = icmp eq i8 %646, 8
  %661 = select i1 %660, i32 -111, i32 4
  %662 = add i32 %654, %661
  %663 = add i32 %662, -1214
  br i1 %660, label %655, label %962

664:                                              ; preds = %651
  %665 = icmp eq i8 %646, 1
  %666 = select i1 %665, i32 8, i32 695
  %667 = add i32 %654, %666
  br i1 %665, label %672, label %668

668:                                              ; preds = %664
  %669 = icmp eq i8 %646, 2
  %670 = select i1 %669, i32 4, i32 28
  %671 = add i32 %667, %670
  br i1 %669, label %957, label %955

672:                                              ; preds = %664
  %673 = inttoptr i32 %534 to i8*
  %674 = load i8, i8* %673, align 1
  %675 = zext i8 %674 to i32
  %676 = add i32 %667, -624
  br label %304

677:                                              ; preds = %691, %204
  %.sroa.892.5 = phi i32 [ %32, %204 ], [ %692, %691 ]
  %.sroa.1109.1 = phi i32 [ 0, %204 ], [ %693, %691 ]
  %.sroa.1225.3 = phi i32 [ 0, %204 ], [ %694, %691 ]
  %678 = phi i32 [ %205, %204 ], [ %697, %691 ]
  %679 = inttoptr i32 %.sroa.892.5 to i8*
  %680 = load i8, i8* %679, align 1
  %681 = and i8 %680, 127
  %682 = zext i8 %681 to i32
  %683 = and i32 %.sroa.1109.1, 31
  %684 = shl i32 %682, 1
  switch i32 %683, label %685 [
    i32 0, label %691
    i32 1, label %689
  ]

685:                                              ; preds = %677
  %686 = add nsw i32 %683, -1
  %687 = shl i32 %682, %686
  %688 = shl i32 %687, 1
  br label %689

689:                                              ; preds = %677, %685
  %690 = phi i32 [ %688, %685 ], [ %684, %677 ]
  br label %691

691:                                              ; preds = %677, %689
  %.sroa.1173.0 = phi i32 [ %690, %689 ], [ %682, %677 ]
  %692 = add i32 %.sroa.892.5, 1
  %693 = add i32 %.sroa.1109.1, 7
  %694 = or i32 %.sroa.1173.0, %.sroa.1225.3
  %695 = add i32 %678, 22
  %696 = icmp sgt i8 %680, -1
  %697 = select i1 %696, i32 %695, i32 %678
  %698 = icmp slt i8 %680, 0
  br i1 %698, label %677, label %699

699:                                              ; preds = %691
  %700 = add i32 %694, -17
  %701 = icmp ne i32 %700, 0
  %702 = lshr i32 %700, 31
  %703 = lshr i32 %694, 31
  %704 = xor i32 %702, %703
  %705 = add nuw nsw i32 %704, %703
  %706 = icmp eq i32 %705, 2
  %707 = icmp sgt i32 %700, -1
  %708 = xor i1 %707, %706
  %709 = and i1 %708, %701
  %710 = select i1 %709, i32 -2055272, i32 9
  %711 = add i32 %697, %710
  br i1 %709, label %44, label %712

712:                                              ; preds = %699
  %713 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -308) to i32*), align 4
  %714 = shl i32 %694, 2
  %715 = add i32 %714, %713
  %716 = inttoptr i32 %715 to i32*
  %717 = load i32, i32* %716, align 4
  %718 = add i32 %713, 99
  %719 = inttoptr i32 %718 to i8*
  %720 = load i8, i8* %719, align 1
  %721 = and i8 %720, 64
  %.not11 = icmp eq i8 %721, 0
  %722 = select i1 %.not11, i32 20, i32 13
  %723 = add i32 %711, %722
  br i1 %.not11, label %732, label %724

724:                                              ; preds = %712
  %725 = add i32 %713, 108
  %726 = add i32 %725, %694
  %727 = inttoptr i32 %726 to i8*
  %728 = load i8, i8* %727, align 1
  %.not6 = icmp eq i8 %728, 0
  %729 = select i1 %.not6, i32 7, i32 23
  %730 = add i32 %723, %729
  %731 = add i32 %730, -747
  br i1 %.not6, label %732, label %304

732:                                              ; preds = %724, %712
  %733 = phi i32 [ %723, %712 ], [ %730, %724 ]
  %734 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -304) to i32*), align 4
  %735 = add i32 %694, %734
  %736 = inttoptr i32 %735 to i8*
  %737 = load i8, i8* %736, align 1
  %738 = icmp eq i8 %737, 4
  %739 = select i1 %738, i32 14, i32 -2055301
  %740 = add i32 %733, %739
  br i1 %738, label %741, label %44

741:                                              ; preds = %732
  %742 = inttoptr i32 %717 to i32*
  %743 = load i32, i32* %742, align 4
  %744 = add i32 %740, -745
  br label %304

745:                                              ; preds = %759, %206
  %.sroa.892.6 = phi i32 [ %32, %206 ], [ %760, %759 ]
  %.sroa.1109.2 = phi i32 [ 0, %206 ], [ %761, %759 ]
  %.sroa.1225.4 = phi i32 [ 0, %206 ], [ %762, %759 ]
  %746 = phi i32 [ %207, %206 ], [ %765, %759 ]
  %747 = inttoptr i32 %.sroa.892.6 to i8*
  %748 = load i8, i8* %747, align 1
  %749 = and i8 %748, 127
  %750 = zext i8 %749 to i32
  %751 = and i32 %.sroa.1109.2, 31
  %752 = shl i32 %750, 1
  switch i32 %751, label %753 [
    i32 0, label %759
    i32 1, label %757
  ]

753:                                              ; preds = %745
  %754 = add nsw i32 %751, -1
  %755 = shl i32 %750, %754
  %756 = shl i32 %755, 1
  br label %757

757:                                              ; preds = %745, %753
  %758 = phi i32 [ %756, %753 ], [ %752, %745 ]
  br label %759

759:                                              ; preds = %745, %757
  %.sroa.1173.1 = phi i32 [ %758, %757 ], [ %750, %745 ]
  %760 = add i32 %.sroa.892.6, 1
  %761 = add i32 %.sroa.1109.2, 7
  %762 = or i32 %.sroa.1173.1, %.sroa.1225.4
  %763 = add i32 %746, 22
  %764 = icmp sgt i8 %748, -1
  %765 = select i1 %764, i32 %763, i32 %746
  %766 = icmp slt i8 %748, 0
  br i1 %766, label %745, label %767

767:                                              ; preds = %759
  %768 = add i32 %746, -768
  br label %304

769:                                              ; preds = %31, %783
  %.sroa.892.7 = phi i32 [ %784, %783 ], [ %32, %31 ]
  %.sroa.1109.3 = phi i32 [ %785, %783 ], [ 0, %31 ]
  %.sroa.1225.5 = phi i32 [ %786, %783 ], [ 0, %31 ]
  %770 = phi i32 [ %789, %783 ], [ %40, %31 ]
  %771 = inttoptr i32 %.sroa.892.7 to i8*
  %772 = load i8, i8* %771, align 1
  %773 = and i8 %772, 127
  %774 = zext i8 %773 to i32
  %775 = and i32 %.sroa.1109.3, 31
  %776 = shl i32 %774, 1
  switch i32 %775, label %777 [
    i32 0, label %783
    i32 1, label %781
  ]

777:                                              ; preds = %769
  %778 = add nsw i32 %775, -1
  %779 = shl i32 %774, %778
  %780 = shl i32 %779, 1
  br label %781

781:                                              ; preds = %769, %777
  %782 = phi i32 [ %780, %777 ], [ %776, %769 ]
  br label %783

783:                                              ; preds = %769, %781
  %.sroa.1173.2 = phi i32 [ %782, %781 ], [ %774, %769 ]
  %784 = add i32 %.sroa.892.7, 1
  %785 = add i32 %.sroa.1109.3, 7
  %786 = or i32 %.sroa.1173.2, %.sroa.1225.5
  %787 = add i32 %770, 22
  %788 = icmp sgt i8 %772, -1
  %789 = select i1 %788, i32 %787, i32 %770
  %790 = icmp slt i8 %772, 0
  br i1 %790, label %769, label %791

791:                                              ; preds = %783
  %792 = add i32 %770, 32
  br label %793

793:                                              ; preds = %807, %791
  %.sroa.892.8 = phi i32 [ %784, %791 ], [ %808, %807 ]
  %.sroa.1109.4 = phi i32 [ 0, %791 ], [ %809, %807 ]
  %.sroa.1330.1 = phi i32 [ 0, %791 ], [ %810, %807 ]
  %794 = phi i32 [ %792, %791 ], [ %813, %807 ]
  %795 = inttoptr i32 %.sroa.892.8 to i8*
  %796 = load i8, i8* %795, align 1
  %797 = and i8 %796, 127
  %798 = zext i8 %797 to i32
  %799 = and i32 %.sroa.1109.4, 31
  %800 = shl i32 %798, 1
  switch i32 %799, label %801 [
    i32 0, label %807
    i32 1, label %805
  ]

801:                                              ; preds = %793
  %802 = add nsw i32 %799, -1
  %803 = shl i32 %798, %802
  %804 = shl i32 %803, 1
  br label %805

805:                                              ; preds = %793, %801
  %806 = phi i32 [ %804, %801 ], [ %800, %793 ]
  br label %807

807:                                              ; preds = %793, %805
  %.sroa.1173.3 = phi i32 [ %806, %805 ], [ %798, %793 ]
  %808 = add i32 %.sroa.892.8, 1
  %809 = add i32 %.sroa.1109.4, 7
  %810 = or i32 %.sroa.1173.3, %.sroa.1330.1
  %811 = add i32 %794, 22
  %812 = icmp sgt i8 %796, -1
  %813 = select i1 %812, i32 %811, i32 %794
  %814 = icmp slt i8 %796, 0
  br i1 %814, label %793, label %815

815:                                              ; preds = %807
  %816 = icmp ugt i32 %809, 31
  %817 = select i1 %816, i32 19, i32 5
  %818 = add i32 %813, %817
  br i1 %816, label %825, label %819

819:                                              ; preds = %815
  %820 = lshr i8 %796, 6
  %821 = and i8 %820, 1
  %.not183 = icmp eq i8 %821, 0
  %822 = select i1 %.not183, i32 14, i32 5
  %823 = add i32 %818, %822
  %824 = icmp eq i8 %821, 0
  br i1 %824, label %825, label %839

825:                                              ; preds = %846, %819, %815
  %.sroa.1330.2 = phi i32 [ %810, %815 ], [ %810, %819 ], [ %848, %846 ]
  %826 = phi i32 [ %818, %815 ], [ %823, %819 ], [ %847, %846 ]
  %827 = add i32 %786, -17
  %828 = icmp ne i32 %827, 0
  %829 = lshr i32 %827, 31
  %830 = lshr i32 %786, 31
  %831 = xor i32 %829, %830
  %832 = add nuw nsw i32 %831, %830
  %833 = icmp eq i32 %832, 2
  %834 = icmp sgt i32 %827, -1
  %835 = xor i1 %834, %833
  %836 = and i1 %835, %828
  %837 = select i1 %836, i32 -2055451, i32 9
  %838 = add i32 %826, %837
  br i1 %836, label %44, label %849

839:                                              ; preds = %819
  %840 = and i32 %809, 31
  switch i32 %840, label %841 [
    i32 0, label %846
    i32 1, label %844
  ]

841:                                              ; preds = %839
  %842 = add nsw i32 %840, -1
  %843 = shl i32 -2, %842
  br label %844

844:                                              ; preds = %839, %841
  %845 = phi i32 [ %843, %841 ], [ -2, %839 ]
  br label %846

846:                                              ; preds = %839, %844
  %.sroa.1173.4 = phi i32 [ %845, %844 ], [ -1, %839 ]
  %847 = add i32 %823, 9
  %848 = or i32 %.sroa.1173.4, %810
  br label %825

849:                                              ; preds = %825
  %850 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -308) to i32*), align 4
  %851 = shl i32 %786, 2
  %852 = add i32 %851, %850
  %853 = inttoptr i32 %852 to i32*
  %854 = load i32, i32* %853, align 4
  %855 = add i32 %850, 99
  %856 = inttoptr i32 %855 to i8*
  %857 = load i8, i8* %856, align 1
  %858 = and i8 %857, 64
  %.not4 = icmp eq i8 %858, 0
  %859 = select i1 %.not4, i32 20, i32 13
  %860 = add i32 %838, %859
  br i1 %.not4, label %869, label %861

861:                                              ; preds = %849
  %862 = add i32 %850, 108
  %863 = add i32 %862, %786
  %864 = inttoptr i32 %863 to i8*
  %865 = load i8, i8* %864, align 1
  %.not5 = icmp eq i8 %865, 0
  %866 = select i1 %.not5, i32 7, i32 23
  %867 = add i32 %860, %866
  %868 = add i32 %867, -926
  br i1 %.not5, label %869, label %878

869:                                              ; preds = %861, %849
  %870 = phi i32 [ %860, %849 ], [ %867, %861 ]
  %871 = load i32, i32* inttoptr (i32 add (i32 ptrtoint (i8* @__anvill_sp to i32), i32 -304) to i32*), align 4
  %872 = add i32 %786, %871
  %873 = inttoptr i32 %872 to i8*
  %874 = load i8, i8* %873, align 1
  %875 = icmp eq i8 %874, 4
  %876 = select i1 %875, i32 14, i32 -2055480
  %877 = add i32 %870, %876
  br i1 %875, label %881, label %44

878:                                              ; preds = %881, %861
  %.sroa.989.7 = phi i32 [ %884, %881 ], [ %854, %861 ]
  %879 = phi i32 [ %885, %881 ], [ %868, %861 ]
  %880 = add i32 %.sroa.1330.2, %.sroa.989.7
  br label %304

881:                                              ; preds = %869
  %882 = inttoptr i32 %854 to i32*
  %883 = add i32 %877, 2
  %884 = load i32, i32* %882, align 4
  %885 = add i32 %883, -926
  br label %878

886:                                              ; preds = %31, %900
  %.sroa.892.9 = phi i32 [ %901, %900 ], [ %32, %31 ]
  %.sroa.989.8 = phi i32 [ %903, %900 ], [ 0, %31 ]
  %.sroa.1109.5 = phi i32 [ %902, %900 ], [ 0, %31 ]
  %887 = phi i32 [ %906, %900 ], [ %40, %31 ]
  %888 = inttoptr i32 %.sroa.892.9 to i8*
  %889 = load i8, i8* %888, align 1
  %890 = and i8 %889, 127
  %891 = zext i8 %890 to i32
  %892 = and i32 %.sroa.1109.5, 31
  %893 = shl i32 %891, 1
  switch i32 %892, label %894 [
    i32 0, label %900
    i32 1, label %898
  ]

894:                                              ; preds = %886
  %895 = add nsw i32 %892, -1
  %896 = shl i32 %891, %895
  %897 = shl i32 %896, 1
  br label %898

898:                                              ; preds = %886, %894
  %899 = phi i32 [ %897, %894 ], [ %893, %886 ]
  br label %900

900:                                              ; preds = %886, %898
  %.sroa.1225.6 = phi i32 [ %899, %898 ], [ %891, %886 ]
  %901 = add i32 %.sroa.892.9, 1
  %902 = add i32 %.sroa.1109.5, 7
  %903 = or i32 %.sroa.1225.6, %.sroa.989.8
  %904 = add i32 %887, 22
  %905 = icmp sgt i8 %889, -1
  %906 = select i1 %905, i32 %904, i32 %887
  %907 = icmp slt i8 %889, 0
  br i1 %907, label %886, label %908

908:                                              ; preds = %900
  %909 = icmp ugt i32 %902, 30
  %910 = icmp ne i32 %.sroa.1109.5, 24
  %911 = and i1 %910, %909
  %912 = select i1 %911, i32 -966, i32 11
  %913 = add i32 %906, %912
  br i1 %911, label %304, label %914

914:                                              ; preds = %908
  %915 = lshr i8 %889, 6
  %916 = and i8 %915, 1
  %.not180 = icmp eq i8 %916, 0
  %917 = select i1 %.not180, i32 -977, i32 9
  %918 = add i32 %913, %917
  %919 = icmp eq i8 %916, 0
  br i1 %919, label %304, label %920

920:                                              ; preds = %914
  %921 = and i32 %902, 31
  switch i32 %921, label %922 [
    i32 0, label %927
    i32 1, label %925
  ]

922:                                              ; preds = %920
  %923 = add nsw i32 %921, -1
  %924 = shl i32 -2, %923
  br label %925

925:                                              ; preds = %920, %922
  %926 = phi i32 [ %924, %922 ], [ -2, %920 ]
  br label %927

927:                                              ; preds = %920, %925
  %.sroa.1173.5 = phi i32 [ %926, %925 ], [ -1, %920 ]
  %928 = or i32 %.sroa.1173.5, %903
  %929 = add i32 %918, -986
  br label %304

930:                                              ; preds = %944, %573
  %.sroa.892.10 = phi i32 [ %32, %573 ], [ %945, %944 ]
  %.sroa.1109.6 = phi i32 [ 0, %573 ], [ %946, %944 ]
  %.sroa.1330.3 = phi i32 [ 0, %573 ], [ %947, %944 ]
  %931 = phi i32 [ %574, %573 ], [ %950, %944 ]
  %932 = inttoptr i32 %.sroa.892.10 to i8*
  %933 = load i8, i8* %932, align 1
  %934 = and i8 %933, 127
  %935 = zext i8 %934 to i32
  %936 = and i32 %.sroa.1109.6, 31
  %937 = shl i32 %935, 1
  switch i32 %936, label %938 [
    i32 0, label %944
    i32 1, label %942
  ]

938:                                              ; preds = %930
  %939 = add nsw i32 %936, -1
  %940 = shl i32 %935, %939
  %941 = shl i32 %940, 1
  br label %942

942:                                              ; preds = %930, %938
  %943 = phi i32 [ %941, %938 ], [ %937, %930 ]
  br label %944

944:                                              ; preds = %930, %942
  %.sroa.1173.6 = phi i32 [ %943, %942 ], [ %935, %930 ]
  %945 = add i32 %.sroa.892.10, 1
  %946 = add i32 %.sroa.1109.6, 7
  %947 = or i32 %.sroa.1173.6, %.sroa.1330.3
  %948 = add i32 %931, 22
  %949 = icmp sgt i8 %933, -1
  %950 = select i1 %949, i32 %948, i32 %931
  %951 = icmp slt i8 %933, 0
  br i1 %951, label %930, label %952

952:                                              ; preds = %944
  %953 = add i32 %947, %534
  %954 = add i32 %931, -1280
  br label %304

955:                                              ; preds = %668
  %956 = add i32 %671, -2055909
  br label %41

957:                                              ; preds = %668
  %958 = inttoptr i32 %534 to i16*
  %959 = load i16, i16* %958, align 2
  %960 = zext i16 %959 to i32
  %961 = add i32 %671, -1315
  br label %304

962:                                              ; preds = %659
  %963 = add i32 %662, -2055899
  br label %41

964:                                              ; preds = %333, %15
  %.sroa.892.11 = phi i32 [ %337, %333 ], [ %14, %15 ]
  ret i32 %.sroa.892.11
}

; Function Attrs: noduplicate noinline nounwind optnone
declare %struct.Memory* @__remill_function_return(%struct.State* nonnull align 1, i32, %struct.Memory*) local_unnamed_addr #1

; Function Attrs: readnone
declare i32 @__anvill_complete_switch(i32, ...) local_unnamed_addr #2

; Function Attrs: nofree nosync nounwind willreturn
declare void @llvm.assume(i1 noundef) #3

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare i32 @llvm.abs.i32(i32, i1 immarg) #4

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { readnone }
attributes #3 = { nofree nosync nounwind willreturn }
attributes #4 = { nofree nosync nounwind readnone speculatable willreturn }
