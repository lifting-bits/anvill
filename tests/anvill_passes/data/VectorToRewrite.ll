target datalayout = "E-m:o-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx-macho"

define <2 x float> @f(<5 x i8> %v1 , <4 x i8> %v2) {
  %.sroa.23.24.vec.expand = shufflevector <5 x i8> %v1, <5 x i8> poison, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 poison, i32 poison, i32 poison, i32 poison>
  %.sroa.23.28.vec.expand = shufflevector <4 x i8> %v2, <4 x i8> poison, <8 x i32> <i32 poison, i32 poison, i32 poison, i32 poison, i32 0, i32 1, i32 2, i32 3>
  %.sroa.23.28.vecblend = shufflevector <8 x i8> %.sroa.23.24.vec.expand, <8 x i8> %.sroa.23.28.vec.expand, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 12, i32 13, i32 14, i32 15>
  %casted = bitcast <8 x i8> %.sroa.23.28.vecblend to <2 x float>
  ret <2 x float> %casted
}