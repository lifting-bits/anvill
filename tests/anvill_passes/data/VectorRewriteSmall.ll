target datalayout = "e-m:o-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx-macho"

define <2 x float> @f(<4 x i8> %v1 , <4 x i8> %v2) {
  %.sroa.23.28.vecblend = shufflevector <4 x i8> %v1, <4 x i8> %v2, <8 x i32> <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7>
  %casted = bitcast <8 x i8> %.sroa.23.28.vecblend to <2 x float>
  ret <2 x float> %casted
}