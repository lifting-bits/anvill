; ModuleID = 'lifted_code'
source_filename = "lifted_code"
target datalayout = "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128"
target triple = "aarch64-apple-macosx-macho"

%struct.State = type { %struct.AArch64State }
%struct.AArch64State = type { %struct.ArchState, %struct.SIMD, i64, %struct.GPR, i64, %union.anon, %union.anon, %union.anon, i64, %struct.SR, i64 }
%struct.ArchState = type { i32, i32, %union.anon }
%struct.SIMD = type { [32 x %union.vec128_t] }
%union.vec128_t = type { %struct.uint128v1_t }
%struct.uint128v1_t = type { [1 x i128] }
%struct.GPR = type { i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg, i64, %struct.Reg }
%struct.Reg = type { %union.anon }
%union.anon = type { i64 }
%struct.SR = type { i64, %struct.Reg, i64, %struct.Reg, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, i8, [6 x i8] }

@__remill_state = external global %struct.State, align 16
@__anvill_reg_X1 = external local_unnamed_addr global i64
@__anvill_reg_X2 = external local_unnamed_addr global i64
@__anvill_reg_X3 = external local_unnamed_addr global i64
@__anvill_reg_X4 = external local_unnamed_addr global i64
@__anvill_reg_X5 = external local_unnamed_addr global i64
@__anvill_reg_X6 = external local_unnamed_addr global i64
@__anvill_reg_X7 = external local_unnamed_addr global i64
@__anvill_reg_X10 = external local_unnamed_addr global i64
@__anvill_reg_X11 = external local_unnamed_addr global i64
@__anvill_reg_X12 = external local_unnamed_addr global i64
@__anvill_reg_X13 = external local_unnamed_addr global i64
@__anvill_reg_X14 = external local_unnamed_addr global i64
@__anvill_reg_X15 = external local_unnamed_addr global i64
@__anvill_reg_X16 = external local_unnamed_addr global i64
@__anvill_reg_X17 = external local_unnamed_addr global i64
@__anvill_reg_X18 = external local_unnamed_addr global i64
@__anvill_reg_V0 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V1 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V2 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V3 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V4 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V5 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V6 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V7 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V16 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V17 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V18 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V19 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V20 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V21 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V22 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V23 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V24 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V25 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V26 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V27 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V28 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V29 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V30 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V31 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_TPIDR_EL0 = external local_unnamed_addr global i64
@__anvill_reg_TPIDRRO_EL0 = external local_unnamed_addr global i64
@__anvill_sp = external global i64
@__anvill_reg_X8 = external local_unnamed_addr global i64
@__anvill_reg_X9 = external local_unnamed_addr global i64
@__anvill_reg_X19 = external local_unnamed_addr global i64
@__anvill_reg_X20 = external local_unnamed_addr global i64
@__anvill_reg_X21 = external local_unnamed_addr global i64
@__anvill_reg_X22 = external local_unnamed_addr global i64
@__anvill_reg_X23 = external local_unnamed_addr global i64
@__anvill_reg_X24 = external local_unnamed_addr global i64
@__anvill_reg_X25 = external local_unnamed_addr global i64
@__anvill_reg_X26 = external local_unnamed_addr global i64
@__anvill_reg_X27 = external local_unnamed_addr global i64
@__anvill_reg_X28 = external local_unnamed_addr global i64
@__anvill_reg_X29 = external local_unnamed_addr global i64
@__anvill_reg_V8 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V9 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V10 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V11 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V12 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V13 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V14 = external local_unnamed_addr global [16 x i8]
@__anvill_reg_V15 = external local_unnamed_addr global [16 x i8]
@__anvill_pc = external global i64
@__anvill_ra = external global i64
@__anvill_reg_X0 = external local_unnamed_addr global i64
@var_100004000__X0_E_CIx4_DI_CIx4_D_F = local_unnamed_addr global <{ [4 x i32], i32, [4 x i32] }> zeroinitializer, !pc !0, !anvill.type !1

; Function Attrs: mustprogress noduplicate noinline nounwind optnone ssp
define void @__remill_intrinsics() local_unnamed_addr #0 {
entry:
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_state) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_read_memory_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_read_memory_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_read_memory_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_read_memory_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_write_memory_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_write_memory_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_write_memory_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_write_memory_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_read_memory_f32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_read_memory_f64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_read_memory_f80) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_read_memory_f128) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_write_memory_f32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_write_memory_f64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_write_memory_f80) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_write_memory_f128) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_barrier_load_load) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_barrier_load_store) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_barrier_store_load) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_barrier_store_store) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_atomic_begin) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_atomic_end) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_delay_slot_begin) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_delay_slot_end) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_exchange_memory_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_exchange_memory_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_exchange_memory_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_exchange_memory_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_add_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_add_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_add_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_add_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_sub_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_sub_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_sub_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_sub_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_or_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_or_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_or_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_or_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_and_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_and_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_and_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_and_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_xor_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_xor_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_xor_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fetch_and_xor_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_fpu_exception_test_and_clear) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_error) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_function_call) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_function_return) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_jump) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_missing_block) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_async_hyper_call) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sync_hyper_call) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_undefined_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_undefined_16) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_undefined_32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_undefined_64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_undefined_f32) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_undefined_f64) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_undefined_f80) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_flag_computation_zero) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_flag_computation_overflow) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_flag_computation_sign) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_flag_computation_carry) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_sle) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_slt) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_sgt) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_sge) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_eq) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_neq) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_ugt) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_uge) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_ult) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_compare_ule) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_segment_es) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_segment_ss) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_segment_ds) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_segment_fs) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_segment_gs) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_debug_reg) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_control_reg_0) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_control_reg_1) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_control_reg_2) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_control_reg_3) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_x86_set_control_reg_4) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_amd64_set_debug_reg) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_amd64_set_control_reg_0) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_amd64_set_control_reg_1) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_amd64_set_control_reg_2) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_amd64_set_control_reg_3) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_amd64_set_control_reg_4) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_amd64_set_control_reg_8) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_aarch64_emulate_instruction) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_aarch32_emulate_instruction) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_aarch32_check_not_el2) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_set_asi_register) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_unimplemented_instruction) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_unhandled_dcti) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_window_underflow) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_a) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_n) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_ne) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_e) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_g) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_le) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_ge) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_l) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_gu) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_leu) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_cc) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_cs) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_pos) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_neg) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_vc) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc_trap_cond_vs) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc32_emulate_instruction) #11
  call void @__remill_mark_as_used(ptr noundef nonnull @__remill_sparc64_emulate_instruction) #11
  ret void
}

declare void @__remill_mark_as_used(ptr noundef) local_unnamed_addr #1

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i8 @__remill_read_memory_8(ptr noundef readnone, i64 noundef) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i16 @__remill_read_memory_16(ptr noundef readnone, i64 noundef) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare i32 @__remill_read_memory_32(ptr noundef readnone, i64 noundef) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare i64 @__remill_read_memory_64(ptr noundef readnone, i64 noundef) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare ptr @__remill_write_memory_8(ptr noundef, i64 noundef, i8 noundef zeroext) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare ptr @__remill_write_memory_16(ptr noundef, i64 noundef, i16 noundef zeroext) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare ptr @__remill_write_memory_32(ptr noundef, i64 noundef, i32 noundef) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare ptr @__remill_write_memory_64(ptr noundef, i64 noundef, i64 noundef) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare float @__remill_read_memory_f32(ptr noundef readnone, i64 noundef) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare double @__remill_read_memory_f64(ptr noundef readnone, i64 noundef) #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare ptr @__remill_read_memory_f80(ptr noundef readnone, i64 noundef, ptr noundef nonnull align 16 dereferenceable(16)) #3

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare double @__remill_read_memory_f128(ptr noundef readnone, i64 noundef) #3

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare ptr @__remill_write_memory_f32(ptr noundef, i64 noundef, float noundef) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare ptr @__remill_write_memory_f64(ptr noundef, i64 noundef, double noundef) #2

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare ptr @__remill_write_memory_f80(ptr noundef, i64 noundef, ptr noundef nonnull align 16 dereferenceable(16)) #3

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare ptr @__remill_write_memory_f128(ptr noundef, i64 noundef, double noundef) #3

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare ptr @__remill_barrier_load_load(ptr noundef) #4

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare ptr @__remill_barrier_load_store(ptr noundef) #2

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare ptr @__remill_barrier_store_load(ptr noundef) #4

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare ptr @__remill_barrier_store_store(ptr noundef) #2

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare ptr @__remill_atomic_begin(ptr noundef readnone) #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare ptr @__remill_atomic_end(ptr noundef readnone) #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare ptr @__remill_delay_slot_begin(ptr noundef) #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare ptr @__remill_delay_slot_end(ptr noundef) #4

declare ptr @__remill_compare_exchange_memory_8(ptr noundef, i64 noundef, ptr noundef nonnull align 1 dereferenceable(1), i8 noundef zeroext) #1

declare ptr @__remill_compare_exchange_memory_16(ptr noundef, i64 noundef, ptr noundef nonnull align 2 dereferenceable(2), i16 noundef zeroext) #1

declare ptr @__remill_compare_exchange_memory_32(ptr noundef, i64 noundef, ptr noundef nonnull align 4 dereferenceable(4), i32 noundef) #1

declare ptr @__remill_compare_exchange_memory_64(ptr noundef, i64 noundef, ptr noundef nonnull align 8 dereferenceable(8), i64 noundef) #1

declare ptr @__remill_fetch_and_add_8(ptr noundef, i64 noundef, ptr noundef nonnull align 1 dereferenceable(1)) #1

declare ptr @__remill_fetch_and_add_16(ptr noundef, i64 noundef, ptr noundef nonnull align 2 dereferenceable(2)) #1

declare ptr @__remill_fetch_and_add_32(ptr noundef, i64 noundef, ptr noundef nonnull align 4 dereferenceable(4)) #1

declare ptr @__remill_fetch_and_add_64(ptr noundef, i64 noundef, ptr noundef nonnull align 8 dereferenceable(8)) #1

declare ptr @__remill_fetch_and_sub_8(ptr noundef, i64 noundef, ptr noundef nonnull align 1 dereferenceable(1)) #1

declare ptr @__remill_fetch_and_sub_16(ptr noundef, i64 noundef, ptr noundef nonnull align 2 dereferenceable(2)) #1

declare ptr @__remill_fetch_and_sub_32(ptr noundef, i64 noundef, ptr noundef nonnull align 4 dereferenceable(4)) #1

declare ptr @__remill_fetch_and_sub_64(ptr noundef, i64 noundef, ptr noundef nonnull align 8 dereferenceable(8)) #1

declare ptr @__remill_fetch_and_or_8(ptr noundef, i64 noundef, ptr noundef nonnull align 1 dereferenceable(1)) #1

declare ptr @__remill_fetch_and_or_16(ptr noundef, i64 noundef, ptr noundef nonnull align 2 dereferenceable(2)) #1

declare ptr @__remill_fetch_and_or_32(ptr noundef, i64 noundef, ptr noundef nonnull align 4 dereferenceable(4)) #1

declare ptr @__remill_fetch_and_or_64(ptr noundef, i64 noundef, ptr noundef nonnull align 8 dereferenceable(8)) #1

declare ptr @__remill_fetch_and_and_8(ptr noundef, i64 noundef, ptr noundef nonnull align 1 dereferenceable(1)) #1

declare ptr @__remill_fetch_and_and_16(ptr noundef, i64 noundef, ptr noundef nonnull align 2 dereferenceable(2)) #1

declare ptr @__remill_fetch_and_and_32(ptr noundef, i64 noundef, ptr noundef nonnull align 4 dereferenceable(4)) #1

declare ptr @__remill_fetch_and_and_64(ptr noundef, i64 noundef, ptr noundef nonnull align 8 dereferenceable(8)) #1

declare ptr @__remill_fetch_and_xor_8(ptr noundef, i64 noundef, ptr noundef nonnull align 1 dereferenceable(1)) #1

declare ptr @__remill_fetch_and_xor_16(ptr noundef, i64 noundef, ptr noundef nonnull align 2 dereferenceable(2)) #1

declare ptr @__remill_fetch_and_xor_32(ptr noundef, i64 noundef, ptr noundef nonnull align 4 dereferenceable(4)) #1

declare ptr @__remill_fetch_and_xor_64(ptr noundef, i64 noundef, ptr noundef nonnull align 8 dereferenceable(8)) #1

; Function Attrs: mustprogress nofree nosync nounwind readnone willreturn
declare i32 @__remill_fpu_exception_test_and_clear(i32 noundef, i32 noundef) #5

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_error(ptr noundef nonnull align 1, i64 noundef, ptr noundef) #6

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_function_call(ptr noundef nonnull align 1, i64 noundef, ptr noundef) #6

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_function_return(ptr noundef nonnull align 1, i64 noundef, ptr noundef) #6

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_jump(ptr noundef nonnull align 1, i64 noundef, ptr noundef) #6

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_missing_block(ptr noundef nonnull align 1, i64 noundef, ptr noundef) #6

; Function Attrs: noduplicate noinline nounwind optnone
declare ptr @__remill_async_hyper_call(ptr noundef nonnull align 1, i64 noundef, ptr noundef) #6

; Function Attrs: alwaysinline mustprogress nounwind
declare dso_local ptr @__remill_sync_hyper_call(ptr noundef nonnull align 16 dereferenceable(1168), ptr noundef, i32 noundef) #7

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i8 @__remill_undefined_8() #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i16 @__remill_undefined_16() #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare i32 @__remill_undefined_32() #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare i64 @__remill_undefined_64() #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare float @__remill_undefined_f32() #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare double @__remill_undefined_f64() #4

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare { i64, i16 } @__remill_undefined_f80() #4

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_zero(i1 noundef zeroext, ...) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_overflow(i1 noundef zeroext, ...) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_sign(i1 noundef zeroext, ...) #2

; Function Attrs: noduplicate noinline nounwind optnone readnone willreturn
declare zeroext i1 @__remill_flag_computation_carry(i1 noundef zeroext, ...) #4

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i1 @__remill_compare_sle(i1 noundef zeroext) #2

; Function Attrs: mustprogress nofree nosync nounwind readnone willreturn
declare zeroext i1 @__remill_compare_slt(i1 noundef zeroext) #5

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i1 @__remill_compare_sgt(i1 noundef zeroext) #2

; Function Attrs: mustprogress nofree nosync nounwind readnone willreturn
declare zeroext i1 @__remill_compare_sge(i1 noundef zeroext) #5

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i1 @__remill_compare_eq(i1 noundef zeroext) #2

; Function Attrs: mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn
declare zeroext i1 @__remill_compare_neq(i1 noundef zeroext) #2

; Function Attrs: mustprogress nofree nosync nounwind readnone willreturn
declare zeroext i1 @__remill_compare_ugt(i1 noundef zeroext) #5

; Function Attrs: mustprogress nofree nosync nounwind readnone willreturn
declare zeroext i1 @__remill_compare_uge(i1 noundef zeroext) #5

; Function Attrs: mustprogress nofree nosync nounwind readnone willreturn
declare zeroext i1 @__remill_compare_ult(i1 noundef zeroext) #5

; Function Attrs: mustprogress nofree nosync nounwind readnone willreturn
declare zeroext i1 @__remill_compare_ule(i1 noundef zeroext) #5

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_segment_es(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_segment_ss(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_segment_ds(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_segment_fs(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_segment_gs(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_debug_reg(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_control_reg_0(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_control_reg_1(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_control_reg_2(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_control_reg_3(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_x86_set_control_reg_4(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_amd64_set_debug_reg(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_amd64_set_control_reg_0(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_amd64_set_control_reg_1(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_amd64_set_control_reg_2(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_amd64_set_control_reg_3(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_amd64_set_control_reg_4(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_amd64_set_control_reg_8(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_aarch64_emulate_instruction(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_aarch32_emulate_instruction(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_aarch32_check_not_el2(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_set_asi_register(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_unimplemented_instruction(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_unhandled_dcti(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_window_underflow(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_a(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_n(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_ne(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_e(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_g(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_le(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_ge(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_l(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_gu(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_leu(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_cc(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_cs(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_pos(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_neg(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_vc(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc_trap_cond_vs(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc32_emulate_instruction(ptr noundef) #8

; Function Attrs: nounwind readnone willreturn
declare ptr @__remill_sparc64_emulate_instruction(ptr noundef) #8

; Function Attrs: noinline
define ptr @basic_block_func4294983420(ptr noalias %stack, i64 %program_counter, ptr %memory, ptr %next_pc_out, ptr noalias %X24, ptr noalias %X22, ptr noalias %X20, ptr noalias %X25, ptr noalias %X28, ptr noalias %X21, ptr noalias %D13, ptr noalias %D9, ptr noalias %D12, ptr noalias %X26, ptr noalias %X29, ptr noalias %D14, ptr noalias %X30, ptr noalias %X19, ptr noalias %D8, ptr noalias %D11, ptr noalias %D15, ptr noalias %X23, ptr noalias %f, ptr noalias %D10, ptr noalias %X27) local_unnamed_addr #9 !__anvill_basic_block_md !4 {
  %1 = load ptr, ptr %f, align 8
  %2 = ptrtoint ptr %1 to i64
  store i64 %2, ptr %stack, align 8
  %3 = add i64 %2, 12
  %4 = inttoptr i64 %3 to ptr
  %5 = load i32, ptr %4, align 4
  %6 = add i64 %2, 16
  %7 = inttoptr i64 %6 to ptr
  store i32 %5, ptr %7, align 4
  call void (...) @__anvill_basic_block_function_return()
  ret ptr %memory
}

; Function Attrs: noinline
define void @sub_100003efc__A_Sv_B_0(ptr %0) local_unnamed_addr #9 !pc !4 {
  %2 = alloca i64, align 8, !pc !4
  %3 = alloca [16 x i8], align 4, !pc !4
  %4 = alloca <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, align 8, !pc !4
  %5 = load i64, ptr @__anvill_reg_X19, align 8, !pc !4
  %6 = load i64, ptr @__anvill_reg_X20, align 8, !pc !4
  %7 = load i64, ptr @__anvill_reg_X21, align 8, !pc !4
  %8 = load i64, ptr @__anvill_reg_X22, align 8, !pc !4
  %9 = load i64, ptr @__anvill_reg_X23, align 8, !pc !4
  %10 = load i64, ptr @__anvill_reg_X24, align 8, !pc !4
  %11 = load i64, ptr @__anvill_reg_X25, align 8, !pc !4
  %12 = load i64, ptr @__anvill_reg_X26, align 8, !pc !4
  %13 = load i64, ptr @__anvill_reg_X27, align 8, !pc !4
  %14 = load i64, ptr @__anvill_reg_X28, align 8, !pc !4
  %15 = load i64, ptr @__anvill_reg_X29, align 8, !pc !4
  %16 = load i8, ptr @__anvill_reg_V8, align 1, !pc !4
  %17 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 1), align 1, !pc !4
  %18 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 2), align 1, !pc !4
  %19 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 3), align 1, !pc !4
  %20 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 4), align 1, !pc !4
  %21 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 5), align 1, !pc !4
  %22 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 6), align 1, !pc !4
  %23 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 7), align 1, !pc !4
  %.sroa.139.144.insert.ext = zext i8 %16 to i64, !pc !4
  %.sroa.139.145.insert.ext = zext i8 %17 to i64, !pc !4
  %.sroa.139.145.insert.shift = shl nuw nsw i64 %.sroa.139.145.insert.ext, 8, !pc !4
  %.sroa.139.145.insert.insert = or i64 %.sroa.139.145.insert.shift, %.sroa.139.144.insert.ext, !pc !4
  %.sroa.139.146.insert.ext = zext i8 %18 to i64, !pc !4
  %.sroa.139.146.insert.shift = shl nuw nsw i64 %.sroa.139.146.insert.ext, 16, !pc !4
  %.sroa.139.146.insert.insert = or i64 %.sroa.139.145.insert.insert, %.sroa.139.146.insert.shift, !pc !4
  %.sroa.139.147.insert.ext = zext i8 %19 to i64, !pc !4
  %.sroa.139.147.insert.shift = shl nuw nsw i64 %.sroa.139.147.insert.ext, 24, !pc !4
  %.sroa.139.147.insert.insert = or i64 %.sroa.139.146.insert.insert, %.sroa.139.147.insert.shift, !pc !4
  %.sroa.139.148.insert.ext = zext i8 %20 to i64, !pc !4
  %.sroa.139.148.insert.shift = shl nuw nsw i64 %.sroa.139.148.insert.ext, 32, !pc !4
  %.sroa.139.149.insert.ext = zext i8 %21 to i64, !pc !4
  %.sroa.139.149.insert.shift = shl nuw nsw i64 %.sroa.139.149.insert.ext, 40, !pc !4
  %.sroa.139.149.insert.mask = or i64 %.sroa.139.147.insert.insert, %.sroa.139.148.insert.shift, !pc !4
  %.sroa.139.150.insert.ext = zext i8 %22 to i64, !pc !4
  %.sroa.139.150.insert.shift = shl nuw nsw i64 %.sroa.139.150.insert.ext, 48, !pc !4
  %.sroa.139.151.insert.ext = zext i8 %23 to i64, !pc !4
  %.sroa.139.151.insert.shift = shl nuw i64 %.sroa.139.151.insert.ext, 56, !pc !4
  %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.149.insert.mask, %.sroa.139.149.insert.shift, !pc !4
  %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.150.insert.shift, !pc !4
  %.sroa.139.159.insert.mask = or i64 %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.151.insert.shift, !pc !4
  %24 = load i8, ptr @__anvill_reg_V9, align 1, !pc !4
  %25 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 1), align 1, !pc !4
  %26 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 2), align 1, !pc !4
  %27 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 3), align 1, !pc !4
  %28 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 4), align 1, !pc !4
  %29 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 5), align 1, !pc !4
  %30 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 6), align 1, !pc !4
  %31 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 7), align 1, !pc !4
  %.sroa.157.160.insert.ext = zext i8 %24 to i64, !pc !4
  %.sroa.157.161.insert.ext = zext i8 %25 to i64, !pc !4
  %.sroa.157.161.insert.shift = shl nuw nsw i64 %.sroa.157.161.insert.ext, 8, !pc !4
  %.sroa.157.161.insert.insert = or i64 %.sroa.157.161.insert.shift, %.sroa.157.160.insert.ext, !pc !4
  %.sroa.157.162.insert.ext = zext i8 %26 to i64, !pc !4
  %.sroa.157.162.insert.shift = shl nuw nsw i64 %.sroa.157.162.insert.ext, 16, !pc !4
  %.sroa.157.162.insert.insert = or i64 %.sroa.157.161.insert.insert, %.sroa.157.162.insert.shift, !pc !4
  %.sroa.157.163.insert.ext = zext i8 %27 to i64, !pc !4
  %.sroa.157.163.insert.shift = shl nuw nsw i64 %.sroa.157.163.insert.ext, 24, !pc !4
  %.sroa.157.163.insert.insert = or i64 %.sroa.157.162.insert.insert, %.sroa.157.163.insert.shift, !pc !4
  %.sroa.157.164.insert.ext = zext i8 %28 to i64, !pc !4
  %.sroa.157.164.insert.shift = shl nuw nsw i64 %.sroa.157.164.insert.ext, 32, !pc !4
  %.sroa.157.165.insert.ext = zext i8 %29 to i64, !pc !4
  %.sroa.157.165.insert.shift = shl nuw nsw i64 %.sroa.157.165.insert.ext, 40, !pc !4
  %.sroa.157.165.insert.mask = or i64 %.sroa.157.163.insert.insert, %.sroa.157.164.insert.shift, !pc !4
  %.sroa.157.166.insert.ext = zext i8 %30 to i64, !pc !4
  %.sroa.157.166.insert.shift = shl nuw nsw i64 %.sroa.157.166.insert.ext, 48, !pc !4
  %.sroa.157.167.insert.ext = zext i8 %31 to i64, !pc !4
  %.sroa.157.167.insert.shift = shl nuw i64 %.sroa.157.167.insert.ext, 56, !pc !4
  %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.165.insert.mask, %.sroa.157.165.insert.shift, !pc !4
  %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.166.insert.shift, !pc !4
  %.sroa.157.175.insert.mask = or i64 %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.167.insert.shift, !pc !4
  %32 = load i8, ptr @__anvill_reg_V10, align 1, !pc !4
  %33 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 1), align 1, !pc !4
  %34 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 2), align 1, !pc !4
  %35 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 3), align 1, !pc !4
  %36 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 4), align 1, !pc !4
  %37 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 5), align 1, !pc !4
  %38 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 6), align 1, !pc !4
  %39 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 7), align 1, !pc !4
  %.sroa.175.176.insert.ext = zext i8 %32 to i64, !pc !4
  %.sroa.175.177.insert.ext = zext i8 %33 to i64, !pc !4
  %.sroa.175.177.insert.shift = shl nuw nsw i64 %.sroa.175.177.insert.ext, 8, !pc !4
  %.sroa.175.177.insert.insert = or i64 %.sroa.175.177.insert.shift, %.sroa.175.176.insert.ext, !pc !4
  %.sroa.175.178.insert.ext = zext i8 %34 to i64, !pc !4
  %.sroa.175.178.insert.shift = shl nuw nsw i64 %.sroa.175.178.insert.ext, 16, !pc !4
  %.sroa.175.178.insert.insert = or i64 %.sroa.175.177.insert.insert, %.sroa.175.178.insert.shift, !pc !4
  %.sroa.175.179.insert.ext = zext i8 %35 to i64, !pc !4
  %.sroa.175.179.insert.shift = shl nuw nsw i64 %.sroa.175.179.insert.ext, 24, !pc !4
  %.sroa.175.179.insert.insert = or i64 %.sroa.175.178.insert.insert, %.sroa.175.179.insert.shift, !pc !4
  %.sroa.175.180.insert.ext = zext i8 %36 to i64, !pc !4
  %.sroa.175.180.insert.shift = shl nuw nsw i64 %.sroa.175.180.insert.ext, 32, !pc !4
  %.sroa.175.181.insert.ext = zext i8 %37 to i64, !pc !4
  %.sroa.175.181.insert.shift = shl nuw nsw i64 %.sroa.175.181.insert.ext, 40, !pc !4
  %.sroa.175.181.insert.mask = or i64 %.sroa.175.179.insert.insert, %.sroa.175.180.insert.shift, !pc !4
  %.sroa.175.182.insert.ext = zext i8 %38 to i64, !pc !4
  %.sroa.175.182.insert.shift = shl nuw nsw i64 %.sroa.175.182.insert.ext, 48, !pc !4
  %.sroa.175.183.insert.ext = zext i8 %39 to i64, !pc !4
  %.sroa.175.183.insert.shift = shl nuw i64 %.sroa.175.183.insert.ext, 56, !pc !4
  %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.181.insert.mask, %.sroa.175.181.insert.shift, !pc !4
  %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.182.insert.shift, !pc !4
  %.sroa.175.191.insert.mask = or i64 %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.183.insert.shift, !pc !4
  %40 = load i8, ptr @__anvill_reg_V11, align 1, !pc !4
  %41 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 1), align 1, !pc !4
  %42 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 2), align 1, !pc !4
  %43 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 3), align 1, !pc !4
  %44 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 4), align 1, !pc !4
  %45 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 5), align 1, !pc !4
  %46 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 6), align 1, !pc !4
  %47 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 7), align 1, !pc !4
  %.sroa.193.192.insert.ext = zext i8 %40 to i64, !pc !4
  %.sroa.193.193.insert.ext = zext i8 %41 to i64, !pc !4
  %.sroa.193.193.insert.shift = shl nuw nsw i64 %.sroa.193.193.insert.ext, 8, !pc !4
  %.sroa.193.193.insert.insert = or i64 %.sroa.193.193.insert.shift, %.sroa.193.192.insert.ext, !pc !4
  %.sroa.193.194.insert.ext = zext i8 %42 to i64, !pc !4
  %.sroa.193.194.insert.shift = shl nuw nsw i64 %.sroa.193.194.insert.ext, 16, !pc !4
  %.sroa.193.194.insert.insert = or i64 %.sroa.193.193.insert.insert, %.sroa.193.194.insert.shift, !pc !4
  %.sroa.193.195.insert.ext = zext i8 %43 to i64, !pc !4
  %.sroa.193.195.insert.shift = shl nuw nsw i64 %.sroa.193.195.insert.ext, 24, !pc !4
  %.sroa.193.195.insert.insert = or i64 %.sroa.193.194.insert.insert, %.sroa.193.195.insert.shift, !pc !4
  %.sroa.193.196.insert.ext = zext i8 %44 to i64, !pc !4
  %.sroa.193.196.insert.shift = shl nuw nsw i64 %.sroa.193.196.insert.ext, 32, !pc !4
  %.sroa.193.197.insert.ext = zext i8 %45 to i64, !pc !4
  %.sroa.193.197.insert.shift = shl nuw nsw i64 %.sroa.193.197.insert.ext, 40, !pc !4
  %.sroa.193.197.insert.mask = or i64 %.sroa.193.195.insert.insert, %.sroa.193.196.insert.shift, !pc !4
  %.sroa.193.198.insert.ext = zext i8 %46 to i64, !pc !4
  %.sroa.193.198.insert.shift = shl nuw nsw i64 %.sroa.193.198.insert.ext, 48, !pc !4
  %.sroa.193.199.insert.ext = zext i8 %47 to i64, !pc !4
  %.sroa.193.199.insert.shift = shl nuw i64 %.sroa.193.199.insert.ext, 56, !pc !4
  %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.197.insert.mask, %.sroa.193.197.insert.shift, !pc !4
  %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.198.insert.shift, !pc !4
  %.sroa.193.207.insert.mask = or i64 %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.199.insert.shift, !pc !4
  %48 = load i8, ptr @__anvill_reg_V12, align 1, !pc !4
  %49 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 1), align 1, !pc !4
  %50 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 2), align 1, !pc !4
  %51 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 3), align 1, !pc !4
  %52 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 4), align 1, !pc !4
  %53 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 5), align 1, !pc !4
  %54 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 6), align 1, !pc !4
  %55 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 7), align 1, !pc !4
  %.sroa.211.208.insert.ext = zext i8 %48 to i64, !pc !4
  %.sroa.211.209.insert.ext = zext i8 %49 to i64, !pc !4
  %.sroa.211.209.insert.shift = shl nuw nsw i64 %.sroa.211.209.insert.ext, 8, !pc !4
  %.sroa.211.209.insert.insert = or i64 %.sroa.211.209.insert.shift, %.sroa.211.208.insert.ext, !pc !4
  %.sroa.211.210.insert.ext = zext i8 %50 to i64, !pc !4
  %.sroa.211.210.insert.shift = shl nuw nsw i64 %.sroa.211.210.insert.ext, 16, !pc !4
  %.sroa.211.210.insert.insert = or i64 %.sroa.211.209.insert.insert, %.sroa.211.210.insert.shift, !pc !4
  %.sroa.211.211.insert.ext = zext i8 %51 to i64, !pc !4
  %.sroa.211.211.insert.shift = shl nuw nsw i64 %.sroa.211.211.insert.ext, 24, !pc !4
  %.sroa.211.211.insert.insert = or i64 %.sroa.211.210.insert.insert, %.sroa.211.211.insert.shift, !pc !4
  %.sroa.211.212.insert.ext = zext i8 %52 to i64, !pc !4
  %.sroa.211.212.insert.shift = shl nuw nsw i64 %.sroa.211.212.insert.ext, 32, !pc !4
  %.sroa.211.213.insert.ext = zext i8 %53 to i64, !pc !4
  %.sroa.211.213.insert.shift = shl nuw nsw i64 %.sroa.211.213.insert.ext, 40, !pc !4
  %.sroa.211.213.insert.mask = or i64 %.sroa.211.211.insert.insert, %.sroa.211.212.insert.shift, !pc !4
  %.sroa.211.214.insert.ext = zext i8 %54 to i64, !pc !4
  %.sroa.211.214.insert.shift = shl nuw nsw i64 %.sroa.211.214.insert.ext, 48, !pc !4
  %.sroa.211.215.insert.ext = zext i8 %55 to i64, !pc !4
  %.sroa.211.215.insert.shift = shl nuw i64 %.sroa.211.215.insert.ext, 56, !pc !4
  %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.213.insert.mask, %.sroa.211.213.insert.shift, !pc !4
  %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.214.insert.shift, !pc !4
  %.sroa.211.223.insert.mask = or i64 %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.215.insert.shift, !pc !4
  %56 = load i8, ptr @__anvill_reg_V13, align 1, !pc !4
  %57 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 1), align 1, !pc !4
  %58 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 2), align 1, !pc !4
  %59 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 3), align 1, !pc !4
  %60 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 4), align 1, !pc !4
  %61 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 5), align 1, !pc !4
  %62 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 6), align 1, !pc !4
  %63 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 7), align 1, !pc !4
  %.sroa.229.224.insert.ext = zext i8 %56 to i64, !pc !4
  %.sroa.229.225.insert.ext = zext i8 %57 to i64, !pc !4
  %.sroa.229.225.insert.shift = shl nuw nsw i64 %.sroa.229.225.insert.ext, 8, !pc !4
  %.sroa.229.225.insert.insert = or i64 %.sroa.229.225.insert.shift, %.sroa.229.224.insert.ext, !pc !4
  %.sroa.229.226.insert.ext = zext i8 %58 to i64, !pc !4
  %.sroa.229.226.insert.shift = shl nuw nsw i64 %.sroa.229.226.insert.ext, 16, !pc !4
  %.sroa.229.226.insert.insert = or i64 %.sroa.229.225.insert.insert, %.sroa.229.226.insert.shift, !pc !4
  %.sroa.229.227.insert.ext = zext i8 %59 to i64, !pc !4
  %.sroa.229.227.insert.shift = shl nuw nsw i64 %.sroa.229.227.insert.ext, 24, !pc !4
  %.sroa.229.227.insert.insert = or i64 %.sroa.229.226.insert.insert, %.sroa.229.227.insert.shift, !pc !4
  %.sroa.229.228.insert.ext = zext i8 %60 to i64, !pc !4
  %.sroa.229.228.insert.shift = shl nuw nsw i64 %.sroa.229.228.insert.ext, 32, !pc !4
  %.sroa.229.229.insert.ext = zext i8 %61 to i64, !pc !4
  %.sroa.229.229.insert.shift = shl nuw nsw i64 %.sroa.229.229.insert.ext, 40, !pc !4
  %.sroa.229.229.insert.mask = or i64 %.sroa.229.227.insert.insert, %.sroa.229.228.insert.shift, !pc !4
  %.sroa.229.230.insert.ext = zext i8 %62 to i64, !pc !4
  %.sroa.229.230.insert.shift = shl nuw nsw i64 %.sroa.229.230.insert.ext, 48, !pc !4
  %.sroa.229.231.insert.ext = zext i8 %63 to i64, !pc !4
  %.sroa.229.231.insert.shift = shl nuw i64 %.sroa.229.231.insert.ext, 56, !pc !4
  %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.229.insert.mask, %.sroa.229.229.insert.shift, !pc !4
  %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.230.insert.shift, !pc !4
  %.sroa.229.239.insert.mask = or i64 %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.231.insert.shift, !pc !4
  %64 = load i8, ptr @__anvill_reg_V14, align 1, !pc !4
  %65 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 1), align 1, !pc !4
  %66 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 2), align 1, !pc !4
  %67 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 3), align 1, !pc !4
  %68 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 4), align 1, !pc !4
  %69 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 5), align 1, !pc !4
  %70 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 6), align 1, !pc !4
  %71 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 7), align 1, !pc !4
  %.sroa.247.240.insert.ext = zext i8 %64 to i64, !pc !4
  %.sroa.247.241.insert.ext = zext i8 %65 to i64, !pc !4
  %.sroa.247.241.insert.shift = shl nuw nsw i64 %.sroa.247.241.insert.ext, 8, !pc !4
  %.sroa.247.241.insert.insert = or i64 %.sroa.247.241.insert.shift, %.sroa.247.240.insert.ext, !pc !4
  %.sroa.247.242.insert.ext = zext i8 %66 to i64, !pc !4
  %.sroa.247.242.insert.shift = shl nuw nsw i64 %.sroa.247.242.insert.ext, 16, !pc !4
  %.sroa.247.242.insert.insert = or i64 %.sroa.247.241.insert.insert, %.sroa.247.242.insert.shift, !pc !4
  %.sroa.247.243.insert.ext = zext i8 %67 to i64, !pc !4
  %.sroa.247.243.insert.shift = shl nuw nsw i64 %.sroa.247.243.insert.ext, 24, !pc !4
  %.sroa.247.243.insert.insert = or i64 %.sroa.247.242.insert.insert, %.sroa.247.243.insert.shift, !pc !4
  %.sroa.247.244.insert.ext = zext i8 %68 to i64, !pc !4
  %.sroa.247.244.insert.shift = shl nuw nsw i64 %.sroa.247.244.insert.ext, 32, !pc !4
  %.sroa.247.245.insert.ext = zext i8 %69 to i64, !pc !4
  %.sroa.247.245.insert.shift = shl nuw nsw i64 %.sroa.247.245.insert.ext, 40, !pc !4
  %.sroa.247.245.insert.mask = or i64 %.sroa.247.243.insert.insert, %.sroa.247.244.insert.shift, !pc !4
  %.sroa.247.246.insert.ext = zext i8 %70 to i64, !pc !4
  %.sroa.247.246.insert.shift = shl nuw nsw i64 %.sroa.247.246.insert.ext, 48, !pc !4
  %.sroa.247.247.insert.ext = zext i8 %71 to i64, !pc !4
  %.sroa.247.247.insert.shift = shl nuw i64 %.sroa.247.247.insert.ext, 56, !pc !4
  %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.245.insert.mask, %.sroa.247.245.insert.shift, !pc !4
  %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.246.insert.shift, !pc !4
  %.sroa.247.255.insert.mask = or i64 %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.247.insert.shift, !pc !4
  %72 = load i8, ptr @__anvill_reg_V15, align 1, !pc !4
  %73 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 1), align 1, !pc !4
  %74 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 2), align 1, !pc !4
  %75 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 3), align 1, !pc !4
  %76 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 4), align 1, !pc !4
  %77 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 5), align 1, !pc !4
  %78 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 6), align 1, !pc !4
  %79 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 7), align 1, !pc !4
  %.sroa.265.256.insert.ext = zext i8 %72 to i64, !pc !4
  %.sroa.265.257.insert.ext = zext i8 %73 to i64, !pc !4
  %.sroa.265.257.insert.shift = shl nuw nsw i64 %.sroa.265.257.insert.ext, 8, !pc !4
  %.sroa.265.257.insert.insert = or i64 %.sroa.265.257.insert.shift, %.sroa.265.256.insert.ext, !pc !4
  %.sroa.265.258.insert.ext = zext i8 %74 to i64, !pc !4
  %.sroa.265.258.insert.shift = shl nuw nsw i64 %.sroa.265.258.insert.ext, 16, !pc !4
  %.sroa.265.258.insert.insert = or i64 %.sroa.265.257.insert.insert, %.sroa.265.258.insert.shift, !pc !4
  %.sroa.265.259.insert.ext = zext i8 %75 to i64, !pc !4
  %.sroa.265.259.insert.shift = shl nuw nsw i64 %.sroa.265.259.insert.ext, 24, !pc !4
  %.sroa.265.259.insert.insert = or i64 %.sroa.265.258.insert.insert, %.sroa.265.259.insert.shift, !pc !4
  %.sroa.265.260.insert.ext = zext i8 %76 to i64, !pc !4
  %.sroa.265.260.insert.shift = shl nuw nsw i64 %.sroa.265.260.insert.ext, 32, !pc !4
  %.sroa.265.261.insert.ext = zext i8 %77 to i64, !pc !4
  %.sroa.265.261.insert.shift = shl nuw nsw i64 %.sroa.265.261.insert.ext, 40, !pc !4
  %.sroa.265.261.insert.mask = or i64 %.sroa.265.259.insert.insert, %.sroa.265.260.insert.shift, !pc !4
  %.sroa.265.262.insert.ext = zext i8 %78 to i64, !pc !4
  %.sroa.265.262.insert.shift = shl nuw nsw i64 %.sroa.265.262.insert.ext, 48, !pc !4
  %.sroa.265.263.insert.ext = zext i8 %79 to i64, !pc !4
  %.sroa.265.263.insert.shift = shl nuw i64 %.sroa.265.263.insert.ext, 56, !pc !4
  %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.261.insert.mask, %.sroa.265.261.insert.shift, !pc !4
  %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.262.insert.shift, !pc !4
  %.sroa.265.271.insert.mask = or i64 %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.263.insert.shift, !pc !4
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %2), !pc !4
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %3), !pc !4
  call void @llvm.lifetime.start.p0(i64 168, ptr nonnull %4), !pc !4
  store i64 ptrtoint (ptr @sub_100003efc__A_Sv_B_0 to i64), ptr %2, align 8, !pc !4
  store i64 %10, ptr %4, align 8, !pc !4
  %80 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 1, !pc !4
  store i64 %8, ptr %80, align 8, !pc !4
  %81 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 2, !pc !4
  store i64 %6, ptr %81, align 8, !pc !4
  %82 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 3, !pc !4
  store i64 %11, ptr %82, align 8, !pc !4
  %83 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 4, !pc !4
  store i64 %14, ptr %83, align 8, !pc !4
  %84 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 5, !pc !4
  store i64 %7, ptr %84, align 8, !pc !4
  %85 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 6, !pc !4
  store i64 %.sroa.229.239.insert.mask, ptr %85, align 8, !pc !4
  %86 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 7, !pc !4
  store i64 %.sroa.157.175.insert.mask, ptr %86, align 8, !pc !4
  %87 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 8, !pc !4
  store i64 %.sroa.211.223.insert.mask, ptr %87, align 8, !pc !4
  %88 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 9, !pc !4
  store i64 %12, ptr %88, align 8, !pc !4
  %89 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 10, !pc !4
  store i64 %15, ptr %89, align 8, !pc !4
  %90 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 11, !pc !4
  store i64 %.sroa.247.255.insert.mask, ptr %90, align 8, !pc !4
  %91 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 12, !pc !4
  store i64 ptrtoint (ptr @__anvill_ra to i64), ptr %91, align 8, !pc !4
  %92 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 13, !pc !4
  store i64 %5, ptr %92, align 8, !pc !4
  %93 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 14, !pc !4
  store i64 %.sroa.139.159.insert.mask, ptr %93, align 8, !pc !4
  %94 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 15, !pc !4
  store i64 %.sroa.193.207.insert.mask, ptr %94, align 8, !pc !4
  %95 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 16, !pc !4
  store i64 %.sroa.265.271.insert.mask, ptr %95, align 8, !pc !4
  %96 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 17, !pc !4
  store i64 %9, ptr %96, align 8, !pc !4
  %97 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 18, !pc !4
  store ptr %0, ptr %97, align 8, !pc !4
  %98 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 19, !pc !4
  store i64 %.sroa.175.191.insert.mask, ptr %98, align 8, !pc !4
  %99 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, ptr, i64, i64 }>, ptr %4, i64 0, i32 20, !pc !4
  store i64 %13, ptr %99, align 8, !pc !4
  %100 = call ptr @basic_block_func4294983420(ptr nonnull %3, i64 ptrtoint (ptr @sub_100003efc__A_Sv_B_0 to i64), ptr null, ptr nonnull %2, ptr nonnull %4, ptr nonnull %80, ptr nonnull %81, ptr nonnull %82, ptr nonnull %83, ptr nonnull %84, ptr nonnull %85, ptr nonnull %86, ptr nonnull %87, ptr nonnull %88, ptr nonnull %89, ptr nonnull %90, ptr nonnull %91, ptr nonnull %92, ptr nonnull %93, ptr nonnull %94, ptr nonnull %95, ptr nonnull %96, ptr nonnull %97, ptr nonnull %98, ptr nonnull %99) #12, !pc !4
  unreachable, !pc !4
}

; Function Attrs: argmemonly nocallback nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture) #10

; Function Attrs: noinline
define ptr @basic_block_func4294983452(ptr noalias %stack, i64 %program_counter, ptr %memory, ptr %next_pc_out, ptr noalias %X24, ptr noalias %X22, ptr noalias %X20, ptr noalias %X25, ptr noalias %X28, ptr noalias %X21, ptr noalias %D13, ptr noalias %D9, ptr noalias %D12, ptr noalias %X26, ptr noalias %X29, ptr noalias %D14, ptr noalias %X30, ptr noalias %X19, ptr noalias %D8, ptr noalias %D11, ptr noalias %D15, ptr noalias %X23, ptr noalias %local_10, ptr noalias %D10, ptr noalias %X27) local_unnamed_addr #9 !__anvill_basic_block_md !5 {
  %1 = getelementptr [16 x i8], ptr %stack, i64 0, i64 8
  %2 = load i64, ptr %X29, align 8
  %3 = load i64, ptr %X30, align 8
  store i64 %2, ptr %local_10, align 8
  store i64 %3, ptr %1, align 8
  call void @sub_100003efc__A_Sv_B_0(ptr nonnull @var_100004000__X0_E_CIx4_DI_CIx4_D_F)
  call void (...) @__anvill_basic_block_function_return()
  ret ptr %memory
}

; Function Attrs: noinline
define void @sub_100003f1c__Avv_B_0() local_unnamed_addr #9 !pc !5 {
  %1 = alloca i64, align 8, !pc !5
  %2 = alloca [16 x i8], align 4, !pc !5
  %3 = alloca <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, align 8, !pc !5
  %4 = load i64, ptr @__anvill_reg_X19, align 8, !pc !5
  %5 = load i64, ptr @__anvill_reg_X20, align 8, !pc !5
  %6 = load i64, ptr @__anvill_reg_X21, align 8, !pc !5
  %7 = load i64, ptr @__anvill_reg_X22, align 8, !pc !5
  %8 = load i64, ptr @__anvill_reg_X23, align 8, !pc !5
  %9 = load i64, ptr @__anvill_reg_X24, align 8, !pc !5
  %10 = load i64, ptr @__anvill_reg_X25, align 8, !pc !5
  %11 = load i64, ptr @__anvill_reg_X26, align 8, !pc !5
  %12 = load i64, ptr @__anvill_reg_X27, align 8, !pc !5
  %13 = load i64, ptr @__anvill_reg_X28, align 8, !pc !5
  %14 = load i64, ptr @__anvill_reg_X29, align 8, !pc !5
  %15 = load i8, ptr @__anvill_reg_V8, align 1, !pc !5
  %16 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 1), align 1, !pc !5
  %17 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 2), align 1, !pc !5
  %18 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 3), align 1, !pc !5
  %19 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 4), align 1, !pc !5
  %20 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 5), align 1, !pc !5
  %21 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 6), align 1, !pc !5
  %22 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 7), align 1, !pc !5
  %.sroa.139.144.insert.ext = zext i8 %15 to i64, !pc !5
  %.sroa.139.145.insert.ext = zext i8 %16 to i64, !pc !5
  %.sroa.139.145.insert.shift = shl nuw nsw i64 %.sroa.139.145.insert.ext, 8, !pc !5
  %.sroa.139.145.insert.insert = or i64 %.sroa.139.145.insert.shift, %.sroa.139.144.insert.ext, !pc !5
  %.sroa.139.146.insert.ext = zext i8 %17 to i64, !pc !5
  %.sroa.139.146.insert.shift = shl nuw nsw i64 %.sroa.139.146.insert.ext, 16, !pc !5
  %.sroa.139.146.insert.insert = or i64 %.sroa.139.145.insert.insert, %.sroa.139.146.insert.shift, !pc !5
  %.sroa.139.147.insert.ext = zext i8 %18 to i64, !pc !5
  %.sroa.139.147.insert.shift = shl nuw nsw i64 %.sroa.139.147.insert.ext, 24, !pc !5
  %.sroa.139.147.insert.insert = or i64 %.sroa.139.146.insert.insert, %.sroa.139.147.insert.shift, !pc !5
  %.sroa.139.148.insert.ext = zext i8 %19 to i64, !pc !5
  %.sroa.139.148.insert.shift = shl nuw nsw i64 %.sroa.139.148.insert.ext, 32, !pc !5
  %.sroa.139.149.insert.ext = zext i8 %20 to i64, !pc !5
  %.sroa.139.149.insert.shift = shl nuw nsw i64 %.sroa.139.149.insert.ext, 40, !pc !5
  %.sroa.139.149.insert.mask = or i64 %.sroa.139.147.insert.insert, %.sroa.139.148.insert.shift, !pc !5
  %.sroa.139.150.insert.ext = zext i8 %21 to i64, !pc !5
  %.sroa.139.150.insert.shift = shl nuw nsw i64 %.sroa.139.150.insert.ext, 48, !pc !5
  %.sroa.139.151.insert.ext = zext i8 %22 to i64, !pc !5
  %.sroa.139.151.insert.shift = shl nuw i64 %.sroa.139.151.insert.ext, 56, !pc !5
  %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.149.insert.mask, %.sroa.139.149.insert.shift, !pc !5
  %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.150.insert.shift, !pc !5
  %.sroa.139.159.insert.mask = or i64 %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.151.insert.shift, !pc !5
  %23 = load i8, ptr @__anvill_reg_V9, align 1, !pc !5
  %24 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 1), align 1, !pc !5
  %25 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 2), align 1, !pc !5
  %26 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 3), align 1, !pc !5
  %27 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 4), align 1, !pc !5
  %28 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 5), align 1, !pc !5
  %29 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 6), align 1, !pc !5
  %30 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 7), align 1, !pc !5
  %.sroa.157.160.insert.ext = zext i8 %23 to i64, !pc !5
  %.sroa.157.161.insert.ext = zext i8 %24 to i64, !pc !5
  %.sroa.157.161.insert.shift = shl nuw nsw i64 %.sroa.157.161.insert.ext, 8, !pc !5
  %.sroa.157.161.insert.insert = or i64 %.sroa.157.161.insert.shift, %.sroa.157.160.insert.ext, !pc !5
  %.sroa.157.162.insert.ext = zext i8 %25 to i64, !pc !5
  %.sroa.157.162.insert.shift = shl nuw nsw i64 %.sroa.157.162.insert.ext, 16, !pc !5
  %.sroa.157.162.insert.insert = or i64 %.sroa.157.161.insert.insert, %.sroa.157.162.insert.shift, !pc !5
  %.sroa.157.163.insert.ext = zext i8 %26 to i64, !pc !5
  %.sroa.157.163.insert.shift = shl nuw nsw i64 %.sroa.157.163.insert.ext, 24, !pc !5
  %.sroa.157.163.insert.insert = or i64 %.sroa.157.162.insert.insert, %.sroa.157.163.insert.shift, !pc !5
  %.sroa.157.164.insert.ext = zext i8 %27 to i64, !pc !5
  %.sroa.157.164.insert.shift = shl nuw nsw i64 %.sroa.157.164.insert.ext, 32, !pc !5
  %.sroa.157.165.insert.ext = zext i8 %28 to i64, !pc !5
  %.sroa.157.165.insert.shift = shl nuw nsw i64 %.sroa.157.165.insert.ext, 40, !pc !5
  %.sroa.157.165.insert.mask = or i64 %.sroa.157.163.insert.insert, %.sroa.157.164.insert.shift, !pc !5
  %.sroa.157.166.insert.ext = zext i8 %29 to i64, !pc !5
  %.sroa.157.166.insert.shift = shl nuw nsw i64 %.sroa.157.166.insert.ext, 48, !pc !5
  %.sroa.157.167.insert.ext = zext i8 %30 to i64, !pc !5
  %.sroa.157.167.insert.shift = shl nuw i64 %.sroa.157.167.insert.ext, 56, !pc !5
  %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.165.insert.mask, %.sroa.157.165.insert.shift, !pc !5
  %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.166.insert.shift, !pc !5
  %.sroa.157.175.insert.mask = or i64 %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.167.insert.shift, !pc !5
  %31 = load i8, ptr @__anvill_reg_V10, align 1, !pc !5
  %32 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 1), align 1, !pc !5
  %33 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 2), align 1, !pc !5
  %34 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 3), align 1, !pc !5
  %35 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 4), align 1, !pc !5
  %36 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 5), align 1, !pc !5
  %37 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 6), align 1, !pc !5
  %38 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 7), align 1, !pc !5
  %.sroa.175.176.insert.ext = zext i8 %31 to i64, !pc !5
  %.sroa.175.177.insert.ext = zext i8 %32 to i64, !pc !5
  %.sroa.175.177.insert.shift = shl nuw nsw i64 %.sroa.175.177.insert.ext, 8, !pc !5
  %.sroa.175.177.insert.insert = or i64 %.sroa.175.177.insert.shift, %.sroa.175.176.insert.ext, !pc !5
  %.sroa.175.178.insert.ext = zext i8 %33 to i64, !pc !5
  %.sroa.175.178.insert.shift = shl nuw nsw i64 %.sroa.175.178.insert.ext, 16, !pc !5
  %.sroa.175.178.insert.insert = or i64 %.sroa.175.177.insert.insert, %.sroa.175.178.insert.shift, !pc !5
  %.sroa.175.179.insert.ext = zext i8 %34 to i64, !pc !5
  %.sroa.175.179.insert.shift = shl nuw nsw i64 %.sroa.175.179.insert.ext, 24, !pc !5
  %.sroa.175.179.insert.insert = or i64 %.sroa.175.178.insert.insert, %.sroa.175.179.insert.shift, !pc !5
  %.sroa.175.180.insert.ext = zext i8 %35 to i64, !pc !5
  %.sroa.175.180.insert.shift = shl nuw nsw i64 %.sroa.175.180.insert.ext, 32, !pc !5
  %.sroa.175.181.insert.ext = zext i8 %36 to i64, !pc !5
  %.sroa.175.181.insert.shift = shl nuw nsw i64 %.sroa.175.181.insert.ext, 40, !pc !5
  %.sroa.175.181.insert.mask = or i64 %.sroa.175.179.insert.insert, %.sroa.175.180.insert.shift, !pc !5
  %.sroa.175.182.insert.ext = zext i8 %37 to i64, !pc !5
  %.sroa.175.182.insert.shift = shl nuw nsw i64 %.sroa.175.182.insert.ext, 48, !pc !5
  %.sroa.175.183.insert.ext = zext i8 %38 to i64, !pc !5
  %.sroa.175.183.insert.shift = shl nuw i64 %.sroa.175.183.insert.ext, 56, !pc !5
  %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.181.insert.mask, %.sroa.175.181.insert.shift, !pc !5
  %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.182.insert.shift, !pc !5
  %.sroa.175.191.insert.mask = or i64 %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.183.insert.shift, !pc !5
  %39 = load i8, ptr @__anvill_reg_V11, align 1, !pc !5
  %40 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 1), align 1, !pc !5
  %41 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 2), align 1, !pc !5
  %42 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 3), align 1, !pc !5
  %43 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 4), align 1, !pc !5
  %44 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 5), align 1, !pc !5
  %45 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 6), align 1, !pc !5
  %46 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 7), align 1, !pc !5
  %.sroa.193.192.insert.ext = zext i8 %39 to i64, !pc !5
  %.sroa.193.193.insert.ext = zext i8 %40 to i64, !pc !5
  %.sroa.193.193.insert.shift = shl nuw nsw i64 %.sroa.193.193.insert.ext, 8, !pc !5
  %.sroa.193.193.insert.insert = or i64 %.sroa.193.193.insert.shift, %.sroa.193.192.insert.ext, !pc !5
  %.sroa.193.194.insert.ext = zext i8 %41 to i64, !pc !5
  %.sroa.193.194.insert.shift = shl nuw nsw i64 %.sroa.193.194.insert.ext, 16, !pc !5
  %.sroa.193.194.insert.insert = or i64 %.sroa.193.193.insert.insert, %.sroa.193.194.insert.shift, !pc !5
  %.sroa.193.195.insert.ext = zext i8 %42 to i64, !pc !5
  %.sroa.193.195.insert.shift = shl nuw nsw i64 %.sroa.193.195.insert.ext, 24, !pc !5
  %.sroa.193.195.insert.insert = or i64 %.sroa.193.194.insert.insert, %.sroa.193.195.insert.shift, !pc !5
  %.sroa.193.196.insert.ext = zext i8 %43 to i64, !pc !5
  %.sroa.193.196.insert.shift = shl nuw nsw i64 %.sroa.193.196.insert.ext, 32, !pc !5
  %.sroa.193.197.insert.ext = zext i8 %44 to i64, !pc !5
  %.sroa.193.197.insert.shift = shl nuw nsw i64 %.sroa.193.197.insert.ext, 40, !pc !5
  %.sroa.193.197.insert.mask = or i64 %.sroa.193.195.insert.insert, %.sroa.193.196.insert.shift, !pc !5
  %.sroa.193.198.insert.ext = zext i8 %45 to i64, !pc !5
  %.sroa.193.198.insert.shift = shl nuw nsw i64 %.sroa.193.198.insert.ext, 48, !pc !5
  %.sroa.193.199.insert.ext = zext i8 %46 to i64, !pc !5
  %.sroa.193.199.insert.shift = shl nuw i64 %.sroa.193.199.insert.ext, 56, !pc !5
  %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.197.insert.mask, %.sroa.193.197.insert.shift, !pc !5
  %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.198.insert.shift, !pc !5
  %.sroa.193.207.insert.mask = or i64 %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.199.insert.shift, !pc !5
  %47 = load i8, ptr @__anvill_reg_V12, align 1, !pc !5
  %48 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 1), align 1, !pc !5
  %49 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 2), align 1, !pc !5
  %50 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 3), align 1, !pc !5
  %51 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 4), align 1, !pc !5
  %52 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 5), align 1, !pc !5
  %53 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 6), align 1, !pc !5
  %54 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 7), align 1, !pc !5
  %.sroa.211.208.insert.ext = zext i8 %47 to i64, !pc !5
  %.sroa.211.209.insert.ext = zext i8 %48 to i64, !pc !5
  %.sroa.211.209.insert.shift = shl nuw nsw i64 %.sroa.211.209.insert.ext, 8, !pc !5
  %.sroa.211.209.insert.insert = or i64 %.sroa.211.209.insert.shift, %.sroa.211.208.insert.ext, !pc !5
  %.sroa.211.210.insert.ext = zext i8 %49 to i64, !pc !5
  %.sroa.211.210.insert.shift = shl nuw nsw i64 %.sroa.211.210.insert.ext, 16, !pc !5
  %.sroa.211.210.insert.insert = or i64 %.sroa.211.209.insert.insert, %.sroa.211.210.insert.shift, !pc !5
  %.sroa.211.211.insert.ext = zext i8 %50 to i64, !pc !5
  %.sroa.211.211.insert.shift = shl nuw nsw i64 %.sroa.211.211.insert.ext, 24, !pc !5
  %.sroa.211.211.insert.insert = or i64 %.sroa.211.210.insert.insert, %.sroa.211.211.insert.shift, !pc !5
  %.sroa.211.212.insert.ext = zext i8 %51 to i64, !pc !5
  %.sroa.211.212.insert.shift = shl nuw nsw i64 %.sroa.211.212.insert.ext, 32, !pc !5
  %.sroa.211.213.insert.ext = zext i8 %52 to i64, !pc !5
  %.sroa.211.213.insert.shift = shl nuw nsw i64 %.sroa.211.213.insert.ext, 40, !pc !5
  %.sroa.211.213.insert.mask = or i64 %.sroa.211.211.insert.insert, %.sroa.211.212.insert.shift, !pc !5
  %.sroa.211.214.insert.ext = zext i8 %53 to i64, !pc !5
  %.sroa.211.214.insert.shift = shl nuw nsw i64 %.sroa.211.214.insert.ext, 48, !pc !5
  %.sroa.211.215.insert.ext = zext i8 %54 to i64, !pc !5
  %.sroa.211.215.insert.shift = shl nuw i64 %.sroa.211.215.insert.ext, 56, !pc !5
  %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.213.insert.mask, %.sroa.211.213.insert.shift, !pc !5
  %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.214.insert.shift, !pc !5
  %.sroa.211.223.insert.mask = or i64 %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.215.insert.shift, !pc !5
  %55 = load i8, ptr @__anvill_reg_V13, align 1, !pc !5
  %56 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 1), align 1, !pc !5
  %57 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 2), align 1, !pc !5
  %58 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 3), align 1, !pc !5
  %59 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 4), align 1, !pc !5
  %60 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 5), align 1, !pc !5
  %61 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 6), align 1, !pc !5
  %62 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 7), align 1, !pc !5
  %.sroa.229.224.insert.ext = zext i8 %55 to i64, !pc !5
  %.sroa.229.225.insert.ext = zext i8 %56 to i64, !pc !5
  %.sroa.229.225.insert.shift = shl nuw nsw i64 %.sroa.229.225.insert.ext, 8, !pc !5
  %.sroa.229.225.insert.insert = or i64 %.sroa.229.225.insert.shift, %.sroa.229.224.insert.ext, !pc !5
  %.sroa.229.226.insert.ext = zext i8 %57 to i64, !pc !5
  %.sroa.229.226.insert.shift = shl nuw nsw i64 %.sroa.229.226.insert.ext, 16, !pc !5
  %.sroa.229.226.insert.insert = or i64 %.sroa.229.225.insert.insert, %.sroa.229.226.insert.shift, !pc !5
  %.sroa.229.227.insert.ext = zext i8 %58 to i64, !pc !5
  %.sroa.229.227.insert.shift = shl nuw nsw i64 %.sroa.229.227.insert.ext, 24, !pc !5
  %.sroa.229.227.insert.insert = or i64 %.sroa.229.226.insert.insert, %.sroa.229.227.insert.shift, !pc !5
  %.sroa.229.228.insert.ext = zext i8 %59 to i64, !pc !5
  %.sroa.229.228.insert.shift = shl nuw nsw i64 %.sroa.229.228.insert.ext, 32, !pc !5
  %.sroa.229.229.insert.ext = zext i8 %60 to i64, !pc !5
  %.sroa.229.229.insert.shift = shl nuw nsw i64 %.sroa.229.229.insert.ext, 40, !pc !5
  %.sroa.229.229.insert.mask = or i64 %.sroa.229.227.insert.insert, %.sroa.229.228.insert.shift, !pc !5
  %.sroa.229.230.insert.ext = zext i8 %61 to i64, !pc !5
  %.sroa.229.230.insert.shift = shl nuw nsw i64 %.sroa.229.230.insert.ext, 48, !pc !5
  %.sroa.229.231.insert.ext = zext i8 %62 to i64, !pc !5
  %.sroa.229.231.insert.shift = shl nuw i64 %.sroa.229.231.insert.ext, 56, !pc !5
  %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.229.insert.mask, %.sroa.229.229.insert.shift, !pc !5
  %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.230.insert.shift, !pc !5
  %.sroa.229.239.insert.mask = or i64 %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.231.insert.shift, !pc !5
  %63 = load i8, ptr @__anvill_reg_V14, align 1, !pc !5
  %64 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 1), align 1, !pc !5
  %65 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 2), align 1, !pc !5
  %66 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 3), align 1, !pc !5
  %67 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 4), align 1, !pc !5
  %68 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 5), align 1, !pc !5
  %69 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 6), align 1, !pc !5
  %70 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 7), align 1, !pc !5
  %.sroa.247.240.insert.ext = zext i8 %63 to i64, !pc !5
  %.sroa.247.241.insert.ext = zext i8 %64 to i64, !pc !5
  %.sroa.247.241.insert.shift = shl nuw nsw i64 %.sroa.247.241.insert.ext, 8, !pc !5
  %.sroa.247.241.insert.insert = or i64 %.sroa.247.241.insert.shift, %.sroa.247.240.insert.ext, !pc !5
  %.sroa.247.242.insert.ext = zext i8 %65 to i64, !pc !5
  %.sroa.247.242.insert.shift = shl nuw nsw i64 %.sroa.247.242.insert.ext, 16, !pc !5
  %.sroa.247.242.insert.insert = or i64 %.sroa.247.241.insert.insert, %.sroa.247.242.insert.shift, !pc !5
  %.sroa.247.243.insert.ext = zext i8 %66 to i64, !pc !5
  %.sroa.247.243.insert.shift = shl nuw nsw i64 %.sroa.247.243.insert.ext, 24, !pc !5
  %.sroa.247.243.insert.insert = or i64 %.sroa.247.242.insert.insert, %.sroa.247.243.insert.shift, !pc !5
  %.sroa.247.244.insert.ext = zext i8 %67 to i64, !pc !5
  %.sroa.247.244.insert.shift = shl nuw nsw i64 %.sroa.247.244.insert.ext, 32, !pc !5
  %.sroa.247.245.insert.ext = zext i8 %68 to i64, !pc !5
  %.sroa.247.245.insert.shift = shl nuw nsw i64 %.sroa.247.245.insert.ext, 40, !pc !5
  %.sroa.247.245.insert.mask = or i64 %.sroa.247.243.insert.insert, %.sroa.247.244.insert.shift, !pc !5
  %.sroa.247.246.insert.ext = zext i8 %69 to i64, !pc !5
  %.sroa.247.246.insert.shift = shl nuw nsw i64 %.sroa.247.246.insert.ext, 48, !pc !5
  %.sroa.247.247.insert.ext = zext i8 %70 to i64, !pc !5
  %.sroa.247.247.insert.shift = shl nuw i64 %.sroa.247.247.insert.ext, 56, !pc !5
  %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.245.insert.mask, %.sroa.247.245.insert.shift, !pc !5
  %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.246.insert.shift, !pc !5
  %.sroa.247.255.insert.mask = or i64 %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.247.insert.shift, !pc !5
  %71 = load i8, ptr @__anvill_reg_V15, align 1, !pc !5
  %72 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 1), align 1, !pc !5
  %73 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 2), align 1, !pc !5
  %74 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 3), align 1, !pc !5
  %75 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 4), align 1, !pc !5
  %76 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 5), align 1, !pc !5
  %77 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 6), align 1, !pc !5
  %78 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 7), align 1, !pc !5
  %.sroa.265.256.insert.ext = zext i8 %71 to i64, !pc !5
  %.sroa.265.257.insert.ext = zext i8 %72 to i64, !pc !5
  %.sroa.265.257.insert.shift = shl nuw nsw i64 %.sroa.265.257.insert.ext, 8, !pc !5
  %.sroa.265.257.insert.insert = or i64 %.sroa.265.257.insert.shift, %.sroa.265.256.insert.ext, !pc !5
  %.sroa.265.258.insert.ext = zext i8 %73 to i64, !pc !5
  %.sroa.265.258.insert.shift = shl nuw nsw i64 %.sroa.265.258.insert.ext, 16, !pc !5
  %.sroa.265.258.insert.insert = or i64 %.sroa.265.257.insert.insert, %.sroa.265.258.insert.shift, !pc !5
  %.sroa.265.259.insert.ext = zext i8 %74 to i64, !pc !5
  %.sroa.265.259.insert.shift = shl nuw nsw i64 %.sroa.265.259.insert.ext, 24, !pc !5
  %.sroa.265.259.insert.insert = or i64 %.sroa.265.258.insert.insert, %.sroa.265.259.insert.shift, !pc !5
  %.sroa.265.260.insert.ext = zext i8 %75 to i64, !pc !5
  %.sroa.265.260.insert.shift = shl nuw nsw i64 %.sroa.265.260.insert.ext, 32, !pc !5
  %.sroa.265.261.insert.ext = zext i8 %76 to i64, !pc !5
  %.sroa.265.261.insert.shift = shl nuw nsw i64 %.sroa.265.261.insert.ext, 40, !pc !5
  %.sroa.265.261.insert.mask = or i64 %.sroa.265.259.insert.insert, %.sroa.265.260.insert.shift, !pc !5
  %.sroa.265.262.insert.ext = zext i8 %77 to i64, !pc !5
  %.sroa.265.262.insert.shift = shl nuw nsw i64 %.sroa.265.262.insert.ext, 48, !pc !5
  %.sroa.265.263.insert.ext = zext i8 %78 to i64, !pc !5
  %.sroa.265.263.insert.shift = shl nuw i64 %.sroa.265.263.insert.ext, 56, !pc !5
  %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.261.insert.mask, %.sroa.265.261.insert.shift, !pc !5
  %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.262.insert.shift, !pc !5
  %.sroa.265.271.insert.mask = or i64 %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.263.insert.shift, !pc !5
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %1), !pc !5
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %2), !pc !5
  call void @llvm.lifetime.start.p0(i64 168, ptr nonnull %3), !pc !5
  store i64 ptrtoint (ptr @sub_100003f1c__Avv_B_0 to i64), ptr %1, align 8, !pc !5
  store i64 %9, ptr %3, align 8, !pc !5
  %79 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 1, !pc !5
  store i64 %7, ptr %79, align 8, !pc !5
  %80 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 2, !pc !5
  store i64 %5, ptr %80, align 8, !pc !5
  %81 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 3, !pc !5
  store i64 %10, ptr %81, align 8, !pc !5
  %82 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 4, !pc !5
  store i64 %13, ptr %82, align 8, !pc !5
  %83 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 5, !pc !5
  store i64 %6, ptr %83, align 8, !pc !5
  %84 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 6, !pc !5
  store i64 %.sroa.229.239.insert.mask, ptr %84, align 8, !pc !5
  %85 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 7, !pc !5
  store i64 %.sroa.157.175.insert.mask, ptr %85, align 8, !pc !5
  %86 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 8, !pc !5
  store i64 %.sroa.211.223.insert.mask, ptr %86, align 8, !pc !5
  %87 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 9, !pc !5
  store i64 %11, ptr %87, align 8, !pc !5
  %88 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 10, !pc !5
  store i64 %14, ptr %88, align 8, !pc !5
  %89 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 11, !pc !5
  store i64 %.sroa.247.255.insert.mask, ptr %89, align 8, !pc !5
  %90 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 12, !pc !5
  store i64 ptrtoint (ptr @__anvill_ra to i64), ptr %90, align 8, !pc !5
  %91 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 13, !pc !5
  store i64 %4, ptr %91, align 8, !pc !5
  %92 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 14, !pc !5
  store i64 %.sroa.139.159.insert.mask, ptr %92, align 8, !pc !5
  %93 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 15, !pc !5
  store i64 %.sroa.193.207.insert.mask, ptr %93, align 8, !pc !5
  %94 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 16, !pc !5
  store i64 %.sroa.265.271.insert.mask, ptr %94, align 8, !pc !5
  %95 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 17, !pc !5
  store i64 %8, ptr %95, align 8, !pc !5
  %96 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 19, !pc !5
  store i64 %.sroa.175.191.insert.mask, ptr %96, align 8, !pc !5
  %97 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 20, !pc !5
  store i64 %12, ptr %97, align 8, !pc !5
  %98 = call ptr @basic_block_func4294983452(ptr nonnull %2, i64 ptrtoint (ptr @sub_100003f1c__Avv_B_0 to i64), ptr null, ptr nonnull %1, ptr nonnull %3, ptr nonnull %79, ptr nonnull %80, ptr nonnull %81, ptr nonnull %82, ptr nonnull %83, ptr nonnull %84, ptr nonnull %85, ptr nonnull %86, ptr nonnull %87, ptr nonnull %88, ptr nonnull %89, ptr nonnull %90, ptr nonnull %91, ptr nonnull %92, ptr nonnull %93, ptr nonnull %94, ptr nonnull %95, ptr nonnull %2, ptr nonnull %96, ptr nonnull %97) #12, !pc !5
  unreachable, !pc !5
}

; Function Attrs: noinline
define ptr @basic_block_func4294983480(ptr noalias %stack, i64 %program_counter, ptr %memory, ptr %next_pc_out, ptr noalias %X24, ptr noalias %X22, ptr noalias %X20, ptr noalias %X25, ptr noalias %X28, ptr noalias %X21, ptr noalias %D9, ptr noalias %D12, ptr noalias %X26, ptr noalias %X29, ptr noalias %D14, ptr noalias %X30, ptr noalias %X19, ptr noalias %D8, ptr noalias %D11, ptr noalias %D15, ptr noalias %X23, ptr noalias %local_10, ptr noalias %D10, ptr noalias %X27, ptr noalias %D13, ptr noalias %local_24) local_unnamed_addr #9 !__anvill_basic_block_md !6 {
  %1 = alloca [28 x i8], align 4
  %2 = getelementptr [36 x i8], ptr %stack, i64 0, i64 28
  %3 = getelementptr inbounds [28 x i8], ptr %1, i64 0, i64 12
  %4 = load i64, ptr %X29, align 8
  %5 = load i64, ptr %X30, align 8
  store i64 %4, ptr %local_10, align 8
  store i64 %5, ptr %2, align 8
  call void @sub_100003efc__A_Sv_B_0(ptr nonnull %3)
  %6 = load i32, ptr %local_24, align 4
  call void (...) @__anvill_basic_block_function_return(i32 %6)
  ret ptr %memory
}

; Function Attrs: noinline
define i32 @sub_100003f38__AvI_B_0() local_unnamed_addr #9 !pc !6 {
  %1 = alloca i64, align 8, !pc !6
  %2 = alloca [64 x i8], align 4, !pc !6
  %3 = alloca <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, align 8, !pc !6
  %4 = load i64, ptr @__anvill_reg_X19, align 8, !pc !6
  %5 = load i64, ptr @__anvill_reg_X20, align 8, !pc !6
  %6 = load i64, ptr @__anvill_reg_X21, align 8, !pc !6
  %7 = load i64, ptr @__anvill_reg_X22, align 8, !pc !6
  %8 = load i64, ptr @__anvill_reg_X23, align 8, !pc !6
  %9 = load i64, ptr @__anvill_reg_X24, align 8, !pc !6
  %10 = load i64, ptr @__anvill_reg_X25, align 8, !pc !6
  %11 = load i64, ptr @__anvill_reg_X26, align 8, !pc !6
  %12 = load i64, ptr @__anvill_reg_X27, align 8, !pc !6
  %13 = load i64, ptr @__anvill_reg_X28, align 8, !pc !6
  %14 = load i64, ptr @__anvill_reg_X29, align 8, !pc !6
  %15 = load i8, ptr @__anvill_reg_V8, align 1, !pc !6
  %16 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 1), align 1, !pc !6
  %17 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 2), align 1, !pc !6
  %18 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 3), align 1, !pc !6
  %19 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 4), align 1, !pc !6
  %20 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 5), align 1, !pc !6
  %21 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 6), align 1, !pc !6
  %22 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 7), align 1, !pc !6
  %.sroa.139.144.insert.ext = zext i8 %15 to i64, !pc !6
  %.sroa.139.145.insert.ext = zext i8 %16 to i64, !pc !6
  %.sroa.139.145.insert.shift = shl nuw nsw i64 %.sroa.139.145.insert.ext, 8, !pc !6
  %.sroa.139.145.insert.insert = or i64 %.sroa.139.145.insert.shift, %.sroa.139.144.insert.ext, !pc !6
  %.sroa.139.146.insert.ext = zext i8 %17 to i64, !pc !6
  %.sroa.139.146.insert.shift = shl nuw nsw i64 %.sroa.139.146.insert.ext, 16, !pc !6
  %.sroa.139.146.insert.insert = or i64 %.sroa.139.145.insert.insert, %.sroa.139.146.insert.shift, !pc !6
  %.sroa.139.147.insert.ext = zext i8 %18 to i64, !pc !6
  %.sroa.139.147.insert.shift = shl nuw nsw i64 %.sroa.139.147.insert.ext, 24, !pc !6
  %.sroa.139.147.insert.insert = or i64 %.sroa.139.146.insert.insert, %.sroa.139.147.insert.shift, !pc !6
  %.sroa.139.148.insert.ext = zext i8 %19 to i64, !pc !6
  %.sroa.139.148.insert.shift = shl nuw nsw i64 %.sroa.139.148.insert.ext, 32, !pc !6
  %.sroa.139.149.insert.ext = zext i8 %20 to i64, !pc !6
  %.sroa.139.149.insert.shift = shl nuw nsw i64 %.sroa.139.149.insert.ext, 40, !pc !6
  %.sroa.139.149.insert.mask = or i64 %.sroa.139.147.insert.insert, %.sroa.139.148.insert.shift, !pc !6
  %.sroa.139.150.insert.ext = zext i8 %21 to i64, !pc !6
  %.sroa.139.150.insert.shift = shl nuw nsw i64 %.sroa.139.150.insert.ext, 48, !pc !6
  %.sroa.139.151.insert.ext = zext i8 %22 to i64, !pc !6
  %.sroa.139.151.insert.shift = shl nuw i64 %.sroa.139.151.insert.ext, 56, !pc !6
  %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.149.insert.mask, %.sroa.139.149.insert.shift, !pc !6
  %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.150.insert.shift, !pc !6
  %.sroa.139.159.insert.mask = or i64 %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.151.insert.shift, !pc !6
  %23 = load i8, ptr @__anvill_reg_V9, align 1, !pc !6
  %24 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 1), align 1, !pc !6
  %25 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 2), align 1, !pc !6
  %26 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 3), align 1, !pc !6
  %27 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 4), align 1, !pc !6
  %28 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 5), align 1, !pc !6
  %29 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 6), align 1, !pc !6
  %30 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 7), align 1, !pc !6
  %.sroa.157.160.insert.ext = zext i8 %23 to i64, !pc !6
  %.sroa.157.161.insert.ext = zext i8 %24 to i64, !pc !6
  %.sroa.157.161.insert.shift = shl nuw nsw i64 %.sroa.157.161.insert.ext, 8, !pc !6
  %.sroa.157.161.insert.insert = or i64 %.sroa.157.161.insert.shift, %.sroa.157.160.insert.ext, !pc !6
  %.sroa.157.162.insert.ext = zext i8 %25 to i64, !pc !6
  %.sroa.157.162.insert.shift = shl nuw nsw i64 %.sroa.157.162.insert.ext, 16, !pc !6
  %.sroa.157.162.insert.insert = or i64 %.sroa.157.161.insert.insert, %.sroa.157.162.insert.shift, !pc !6
  %.sroa.157.163.insert.ext = zext i8 %26 to i64, !pc !6
  %.sroa.157.163.insert.shift = shl nuw nsw i64 %.sroa.157.163.insert.ext, 24, !pc !6
  %.sroa.157.163.insert.insert = or i64 %.sroa.157.162.insert.insert, %.sroa.157.163.insert.shift, !pc !6
  %.sroa.157.164.insert.ext = zext i8 %27 to i64, !pc !6
  %.sroa.157.164.insert.shift = shl nuw nsw i64 %.sroa.157.164.insert.ext, 32, !pc !6
  %.sroa.157.165.insert.ext = zext i8 %28 to i64, !pc !6
  %.sroa.157.165.insert.shift = shl nuw nsw i64 %.sroa.157.165.insert.ext, 40, !pc !6
  %.sroa.157.165.insert.mask = or i64 %.sroa.157.163.insert.insert, %.sroa.157.164.insert.shift, !pc !6
  %.sroa.157.166.insert.ext = zext i8 %29 to i64, !pc !6
  %.sroa.157.166.insert.shift = shl nuw nsw i64 %.sroa.157.166.insert.ext, 48, !pc !6
  %.sroa.157.167.insert.ext = zext i8 %30 to i64, !pc !6
  %.sroa.157.167.insert.shift = shl nuw i64 %.sroa.157.167.insert.ext, 56, !pc !6
  %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.165.insert.mask, %.sroa.157.165.insert.shift, !pc !6
  %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.166.insert.shift, !pc !6
  %.sroa.157.175.insert.mask = or i64 %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.167.insert.shift, !pc !6
  %31 = load i8, ptr @__anvill_reg_V10, align 1, !pc !6
  %32 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 1), align 1, !pc !6
  %33 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 2), align 1, !pc !6
  %34 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 3), align 1, !pc !6
  %35 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 4), align 1, !pc !6
  %36 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 5), align 1, !pc !6
  %37 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 6), align 1, !pc !6
  %38 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 7), align 1, !pc !6
  %.sroa.175.176.insert.ext = zext i8 %31 to i64, !pc !6
  %.sroa.175.177.insert.ext = zext i8 %32 to i64, !pc !6
  %.sroa.175.177.insert.shift = shl nuw nsw i64 %.sroa.175.177.insert.ext, 8, !pc !6
  %.sroa.175.177.insert.insert = or i64 %.sroa.175.177.insert.shift, %.sroa.175.176.insert.ext, !pc !6
  %.sroa.175.178.insert.ext = zext i8 %33 to i64, !pc !6
  %.sroa.175.178.insert.shift = shl nuw nsw i64 %.sroa.175.178.insert.ext, 16, !pc !6
  %.sroa.175.178.insert.insert = or i64 %.sroa.175.177.insert.insert, %.sroa.175.178.insert.shift, !pc !6
  %.sroa.175.179.insert.ext = zext i8 %34 to i64, !pc !6
  %.sroa.175.179.insert.shift = shl nuw nsw i64 %.sroa.175.179.insert.ext, 24, !pc !6
  %.sroa.175.179.insert.insert = or i64 %.sroa.175.178.insert.insert, %.sroa.175.179.insert.shift, !pc !6
  %.sroa.175.180.insert.ext = zext i8 %35 to i64, !pc !6
  %.sroa.175.180.insert.shift = shl nuw nsw i64 %.sroa.175.180.insert.ext, 32, !pc !6
  %.sroa.175.181.insert.ext = zext i8 %36 to i64, !pc !6
  %.sroa.175.181.insert.shift = shl nuw nsw i64 %.sroa.175.181.insert.ext, 40, !pc !6
  %.sroa.175.181.insert.mask = or i64 %.sroa.175.179.insert.insert, %.sroa.175.180.insert.shift, !pc !6
  %.sroa.175.182.insert.ext = zext i8 %37 to i64, !pc !6
  %.sroa.175.182.insert.shift = shl nuw nsw i64 %.sroa.175.182.insert.ext, 48, !pc !6
  %.sroa.175.183.insert.ext = zext i8 %38 to i64, !pc !6
  %.sroa.175.183.insert.shift = shl nuw i64 %.sroa.175.183.insert.ext, 56, !pc !6
  %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.181.insert.mask, %.sroa.175.181.insert.shift, !pc !6
  %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.182.insert.shift, !pc !6
  %.sroa.175.191.insert.mask = or i64 %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.183.insert.shift, !pc !6
  %39 = load i8, ptr @__anvill_reg_V11, align 1, !pc !6
  %40 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 1), align 1, !pc !6
  %41 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 2), align 1, !pc !6
  %42 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 3), align 1, !pc !6
  %43 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 4), align 1, !pc !6
  %44 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 5), align 1, !pc !6
  %45 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 6), align 1, !pc !6
  %46 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 7), align 1, !pc !6
  %.sroa.193.192.insert.ext = zext i8 %39 to i64, !pc !6
  %.sroa.193.193.insert.ext = zext i8 %40 to i64, !pc !6
  %.sroa.193.193.insert.shift = shl nuw nsw i64 %.sroa.193.193.insert.ext, 8, !pc !6
  %.sroa.193.193.insert.insert = or i64 %.sroa.193.193.insert.shift, %.sroa.193.192.insert.ext, !pc !6
  %.sroa.193.194.insert.ext = zext i8 %41 to i64, !pc !6
  %.sroa.193.194.insert.shift = shl nuw nsw i64 %.sroa.193.194.insert.ext, 16, !pc !6
  %.sroa.193.194.insert.insert = or i64 %.sroa.193.193.insert.insert, %.sroa.193.194.insert.shift, !pc !6
  %.sroa.193.195.insert.ext = zext i8 %42 to i64, !pc !6
  %.sroa.193.195.insert.shift = shl nuw nsw i64 %.sroa.193.195.insert.ext, 24, !pc !6
  %.sroa.193.195.insert.insert = or i64 %.sroa.193.194.insert.insert, %.sroa.193.195.insert.shift, !pc !6
  %.sroa.193.196.insert.ext = zext i8 %43 to i64, !pc !6
  %.sroa.193.196.insert.shift = shl nuw nsw i64 %.sroa.193.196.insert.ext, 32, !pc !6
  %.sroa.193.197.insert.ext = zext i8 %44 to i64, !pc !6
  %.sroa.193.197.insert.shift = shl nuw nsw i64 %.sroa.193.197.insert.ext, 40, !pc !6
  %.sroa.193.197.insert.mask = or i64 %.sroa.193.195.insert.insert, %.sroa.193.196.insert.shift, !pc !6
  %.sroa.193.198.insert.ext = zext i8 %45 to i64, !pc !6
  %.sroa.193.198.insert.shift = shl nuw nsw i64 %.sroa.193.198.insert.ext, 48, !pc !6
  %.sroa.193.199.insert.ext = zext i8 %46 to i64, !pc !6
  %.sroa.193.199.insert.shift = shl nuw i64 %.sroa.193.199.insert.ext, 56, !pc !6
  %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.197.insert.mask, %.sroa.193.197.insert.shift, !pc !6
  %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.198.insert.shift, !pc !6
  %.sroa.193.207.insert.mask = or i64 %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.199.insert.shift, !pc !6
  %47 = load i8, ptr @__anvill_reg_V12, align 1, !pc !6
  %48 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 1), align 1, !pc !6
  %49 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 2), align 1, !pc !6
  %50 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 3), align 1, !pc !6
  %51 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 4), align 1, !pc !6
  %52 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 5), align 1, !pc !6
  %53 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 6), align 1, !pc !6
  %54 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 7), align 1, !pc !6
  %.sroa.211.208.insert.ext = zext i8 %47 to i64, !pc !6
  %.sroa.211.209.insert.ext = zext i8 %48 to i64, !pc !6
  %.sroa.211.209.insert.shift = shl nuw nsw i64 %.sroa.211.209.insert.ext, 8, !pc !6
  %.sroa.211.209.insert.insert = or i64 %.sroa.211.209.insert.shift, %.sroa.211.208.insert.ext, !pc !6
  %.sroa.211.210.insert.ext = zext i8 %49 to i64, !pc !6
  %.sroa.211.210.insert.shift = shl nuw nsw i64 %.sroa.211.210.insert.ext, 16, !pc !6
  %.sroa.211.210.insert.insert = or i64 %.sroa.211.209.insert.insert, %.sroa.211.210.insert.shift, !pc !6
  %.sroa.211.211.insert.ext = zext i8 %50 to i64, !pc !6
  %.sroa.211.211.insert.shift = shl nuw nsw i64 %.sroa.211.211.insert.ext, 24, !pc !6
  %.sroa.211.211.insert.insert = or i64 %.sroa.211.210.insert.insert, %.sroa.211.211.insert.shift, !pc !6
  %.sroa.211.212.insert.ext = zext i8 %51 to i64, !pc !6
  %.sroa.211.212.insert.shift = shl nuw nsw i64 %.sroa.211.212.insert.ext, 32, !pc !6
  %.sroa.211.213.insert.ext = zext i8 %52 to i64, !pc !6
  %.sroa.211.213.insert.shift = shl nuw nsw i64 %.sroa.211.213.insert.ext, 40, !pc !6
  %.sroa.211.213.insert.mask = or i64 %.sroa.211.211.insert.insert, %.sroa.211.212.insert.shift, !pc !6
  %.sroa.211.214.insert.ext = zext i8 %53 to i64, !pc !6
  %.sroa.211.214.insert.shift = shl nuw nsw i64 %.sroa.211.214.insert.ext, 48, !pc !6
  %.sroa.211.215.insert.ext = zext i8 %54 to i64, !pc !6
  %.sroa.211.215.insert.shift = shl nuw i64 %.sroa.211.215.insert.ext, 56, !pc !6
  %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.213.insert.mask, %.sroa.211.213.insert.shift, !pc !6
  %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.214.insert.shift, !pc !6
  %.sroa.211.223.insert.mask = or i64 %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.215.insert.shift, !pc !6
  %55 = load i8, ptr @__anvill_reg_V13, align 1, !pc !6
  %56 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 1), align 1, !pc !6
  %57 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 2), align 1, !pc !6
  %58 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 3), align 1, !pc !6
  %59 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 4), align 1, !pc !6
  %60 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 5), align 1, !pc !6
  %61 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 6), align 1, !pc !6
  %62 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 7), align 1, !pc !6
  %.sroa.229.224.insert.ext = zext i8 %55 to i64, !pc !6
  %.sroa.229.225.insert.ext = zext i8 %56 to i64, !pc !6
  %.sroa.229.225.insert.shift = shl nuw nsw i64 %.sroa.229.225.insert.ext, 8, !pc !6
  %.sroa.229.225.insert.insert = or i64 %.sroa.229.225.insert.shift, %.sroa.229.224.insert.ext, !pc !6
  %.sroa.229.226.insert.ext = zext i8 %57 to i64, !pc !6
  %.sroa.229.226.insert.shift = shl nuw nsw i64 %.sroa.229.226.insert.ext, 16, !pc !6
  %.sroa.229.226.insert.insert = or i64 %.sroa.229.225.insert.insert, %.sroa.229.226.insert.shift, !pc !6
  %.sroa.229.227.insert.ext = zext i8 %58 to i64, !pc !6
  %.sroa.229.227.insert.shift = shl nuw nsw i64 %.sroa.229.227.insert.ext, 24, !pc !6
  %.sroa.229.227.insert.insert = or i64 %.sroa.229.226.insert.insert, %.sroa.229.227.insert.shift, !pc !6
  %.sroa.229.228.insert.ext = zext i8 %59 to i64, !pc !6
  %.sroa.229.228.insert.shift = shl nuw nsw i64 %.sroa.229.228.insert.ext, 32, !pc !6
  %.sroa.229.229.insert.ext = zext i8 %60 to i64, !pc !6
  %.sroa.229.229.insert.shift = shl nuw nsw i64 %.sroa.229.229.insert.ext, 40, !pc !6
  %.sroa.229.229.insert.mask = or i64 %.sroa.229.227.insert.insert, %.sroa.229.228.insert.shift, !pc !6
  %.sroa.229.230.insert.ext = zext i8 %61 to i64, !pc !6
  %.sroa.229.230.insert.shift = shl nuw nsw i64 %.sroa.229.230.insert.ext, 48, !pc !6
  %.sroa.229.231.insert.ext = zext i8 %62 to i64, !pc !6
  %.sroa.229.231.insert.shift = shl nuw i64 %.sroa.229.231.insert.ext, 56, !pc !6
  %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.229.insert.mask, %.sroa.229.229.insert.shift, !pc !6
  %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.230.insert.shift, !pc !6
  %.sroa.229.239.insert.mask = or i64 %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.231.insert.shift, !pc !6
  %63 = load i8, ptr @__anvill_reg_V14, align 1, !pc !6
  %64 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 1), align 1, !pc !6
  %65 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 2), align 1, !pc !6
  %66 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 3), align 1, !pc !6
  %67 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 4), align 1, !pc !6
  %68 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 5), align 1, !pc !6
  %69 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 6), align 1, !pc !6
  %70 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 7), align 1, !pc !6
  %.sroa.247.240.insert.ext = zext i8 %63 to i64, !pc !6
  %.sroa.247.241.insert.ext = zext i8 %64 to i64, !pc !6
  %.sroa.247.241.insert.shift = shl nuw nsw i64 %.sroa.247.241.insert.ext, 8, !pc !6
  %.sroa.247.241.insert.insert = or i64 %.sroa.247.241.insert.shift, %.sroa.247.240.insert.ext, !pc !6
  %.sroa.247.242.insert.ext = zext i8 %65 to i64, !pc !6
  %.sroa.247.242.insert.shift = shl nuw nsw i64 %.sroa.247.242.insert.ext, 16, !pc !6
  %.sroa.247.242.insert.insert = or i64 %.sroa.247.241.insert.insert, %.sroa.247.242.insert.shift, !pc !6
  %.sroa.247.243.insert.ext = zext i8 %66 to i64, !pc !6
  %.sroa.247.243.insert.shift = shl nuw nsw i64 %.sroa.247.243.insert.ext, 24, !pc !6
  %.sroa.247.243.insert.insert = or i64 %.sroa.247.242.insert.insert, %.sroa.247.243.insert.shift, !pc !6
  %.sroa.247.244.insert.ext = zext i8 %67 to i64, !pc !6
  %.sroa.247.244.insert.shift = shl nuw nsw i64 %.sroa.247.244.insert.ext, 32, !pc !6
  %.sroa.247.245.insert.ext = zext i8 %68 to i64, !pc !6
  %.sroa.247.245.insert.shift = shl nuw nsw i64 %.sroa.247.245.insert.ext, 40, !pc !6
  %.sroa.247.245.insert.mask = or i64 %.sroa.247.243.insert.insert, %.sroa.247.244.insert.shift, !pc !6
  %.sroa.247.246.insert.ext = zext i8 %69 to i64, !pc !6
  %.sroa.247.246.insert.shift = shl nuw nsw i64 %.sroa.247.246.insert.ext, 48, !pc !6
  %.sroa.247.247.insert.ext = zext i8 %70 to i64, !pc !6
  %.sroa.247.247.insert.shift = shl nuw i64 %.sroa.247.247.insert.ext, 56, !pc !6
  %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.245.insert.mask, %.sroa.247.245.insert.shift, !pc !6
  %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.246.insert.shift, !pc !6
  %.sroa.247.255.insert.mask = or i64 %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.247.insert.shift, !pc !6
  %71 = load i8, ptr @__anvill_reg_V15, align 1, !pc !6
  %72 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 1), align 1, !pc !6
  %73 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 2), align 1, !pc !6
  %74 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 3), align 1, !pc !6
  %75 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 4), align 1, !pc !6
  %76 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 5), align 1, !pc !6
  %77 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 6), align 1, !pc !6
  %78 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 7), align 1, !pc !6
  %.sroa.265.256.insert.ext = zext i8 %71 to i64, !pc !6
  %.sroa.265.257.insert.ext = zext i8 %72 to i64, !pc !6
  %.sroa.265.257.insert.shift = shl nuw nsw i64 %.sroa.265.257.insert.ext, 8, !pc !6
  %.sroa.265.257.insert.insert = or i64 %.sroa.265.257.insert.shift, %.sroa.265.256.insert.ext, !pc !6
  %.sroa.265.258.insert.ext = zext i8 %73 to i64, !pc !6
  %.sroa.265.258.insert.shift = shl nuw nsw i64 %.sroa.265.258.insert.ext, 16, !pc !6
  %.sroa.265.258.insert.insert = or i64 %.sroa.265.257.insert.insert, %.sroa.265.258.insert.shift, !pc !6
  %.sroa.265.259.insert.ext = zext i8 %74 to i64, !pc !6
  %.sroa.265.259.insert.shift = shl nuw nsw i64 %.sroa.265.259.insert.ext, 24, !pc !6
  %.sroa.265.259.insert.insert = or i64 %.sroa.265.258.insert.insert, %.sroa.265.259.insert.shift, !pc !6
  %.sroa.265.260.insert.ext = zext i8 %75 to i64, !pc !6
  %.sroa.265.260.insert.shift = shl nuw nsw i64 %.sroa.265.260.insert.ext, 32, !pc !6
  %.sroa.265.261.insert.ext = zext i8 %76 to i64, !pc !6
  %.sroa.265.261.insert.shift = shl nuw nsw i64 %.sroa.265.261.insert.ext, 40, !pc !6
  %.sroa.265.261.insert.mask = or i64 %.sroa.265.259.insert.insert, %.sroa.265.260.insert.shift, !pc !6
  %.sroa.265.262.insert.ext = zext i8 %77 to i64, !pc !6
  %.sroa.265.262.insert.shift = shl nuw nsw i64 %.sroa.265.262.insert.ext, 48, !pc !6
  %.sroa.265.263.insert.ext = zext i8 %78 to i64, !pc !6
  %.sroa.265.263.insert.shift = shl nuw i64 %.sroa.265.263.insert.ext, 56, !pc !6
  %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.261.insert.mask, %.sroa.265.261.insert.shift, !pc !6
  %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.262.insert.shift, !pc !6
  %.sroa.265.271.insert.mask = or i64 %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.263.insert.shift, !pc !6
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %1), !pc !6
  call void @llvm.lifetime.start.p0(i64 64, ptr nonnull %2), !pc !6
  call void @llvm.lifetime.start.p0(i64 172, ptr nonnull %3), !pc !6
  store i64 ptrtoint (ptr @sub_100003f38__AvI_B_0 to i64), ptr %1, align 8, !pc !6
  store i64 %9, ptr %3, align 8, !pc !6
  %79 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 1, !pc !6
  store i64 %7, ptr %79, align 8, !pc !6
  %80 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 2, !pc !6
  store i64 %5, ptr %80, align 8, !pc !6
  %81 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 3, !pc !6
  store i64 %10, ptr %81, align 8, !pc !6
  %82 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 4, !pc !6
  store i64 %13, ptr %82, align 8, !pc !6
  %83 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 5, !pc !6
  store i64 %6, ptr %83, align 8, !pc !6
  %84 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 6, !pc !6
  store i64 %.sroa.157.175.insert.mask, ptr %84, align 8, !pc !6
  %85 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 7, !pc !6
  store i64 %.sroa.211.223.insert.mask, ptr %85, align 8, !pc !6
  %86 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 8, !pc !6
  store i64 %11, ptr %86, align 8, !pc !6
  %87 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 9, !pc !6
  store i64 %14, ptr %87, align 8, !pc !6
  %88 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 10, !pc !6
  store i64 %.sroa.247.255.insert.mask, ptr %88, align 8, !pc !6
  %89 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 11, !pc !6
  store i64 ptrtoint (ptr @__anvill_ra to i64), ptr %89, align 8, !pc !6
  %90 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 12, !pc !6
  store i64 %4, ptr %90, align 8, !pc !6
  %91 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 13, !pc !6
  store i64 %.sroa.139.159.insert.mask, ptr %91, align 8, !pc !6
  %92 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 14, !pc !6
  store i64 %.sroa.193.207.insert.mask, ptr %92, align 8, !pc !6
  %93 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 15, !pc !6
  store i64 %.sroa.265.271.insert.mask, ptr %93, align 8, !pc !6
  %94 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 16, !pc !6
  store i64 %8, ptr %94, align 8, !pc !6
  %95 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 18, !pc !6
  store i64 %.sroa.175.191.insert.mask, ptr %95, align 8, !pc !6
  %96 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 19, !pc !6
  store i64 %12, ptr %96, align 8, !pc !6
  %97 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32 }>, ptr %3, i64 0, i32 20, !pc !6
  store i64 %.sroa.229.239.insert.mask, ptr %97, align 8, !pc !6
  %98 = getelementptr inbounds [64 x i8], ptr %2, i64 0, i64 48, !pc !6
  %99 = getelementptr inbounds [64 x i8], ptr %2, i64 0, i64 28, !pc !6
  %100 = call ptr @basic_block_func4294983480(ptr nonnull %2, i64 ptrtoint (ptr @sub_100003f38__AvI_B_0 to i64), ptr null, ptr nonnull %1, ptr nonnull %3, ptr nonnull %79, ptr nonnull %80, ptr nonnull %81, ptr nonnull %82, ptr nonnull %83, ptr nonnull %84, ptr nonnull %85, ptr nonnull %86, ptr nonnull %87, ptr nonnull %88, ptr nonnull %89, ptr nonnull %90, ptr nonnull %91, ptr nonnull %92, ptr nonnull %93, ptr nonnull %94, ptr nonnull %98, ptr nonnull %95, ptr nonnull %96, ptr nonnull %97, ptr nonnull %99) #12, !pc !6
  unreachable, !pc !6
}

; Function Attrs: noinline
define ptr @basic_block_func4294983516(ptr %stack, i64 %program_counter, ptr %memory, ptr %next_pc_out, ptr noalias %X24, ptr noalias %X22, ptr noalias %X20, ptr noalias %X25, ptr noalias %X28, ptr noalias %X23, ptr noalias %X21, ptr noalias %D13, ptr noalias %D9, ptr noalias %D12, ptr noalias %X26, ptr noalias %X29, ptr noalias %D14, ptr noalias %X30, ptr noalias %X19, ptr noalias %D8, ptr noalias %D11, ptr noalias %D15, ptr noalias %D10, ptr noalias %X27) local_unnamed_addr #9 !__anvill_basic_block_md !7 {
  %1 = load i32, ptr inttoptr (i64 4294983692 to ptr), align 4
  store i32 %1, ptr inttoptr (i64 4294983696 to ptr), align 16
  call void (...) @__anvill_basic_block_function_return()
  ret ptr %memory
}

; Function Attrs: noinline
define void @sub_100003f5c__Avv_B_0() local_unnamed_addr #9 !pc !7 {
  %1 = alloca [0 x i8], align 4, !pc !7
  %2 = alloca i64, align 8, !pc !7
  %3 = alloca <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, align 8, !pc !7
  %4 = load i64, ptr @__anvill_reg_X19, align 8, !pc !7
  %5 = load i64, ptr @__anvill_reg_X20, align 8, !pc !7
  %6 = load i64, ptr @__anvill_reg_X21, align 8, !pc !7
  %7 = load i64, ptr @__anvill_reg_X22, align 8, !pc !7
  %8 = load i64, ptr @__anvill_reg_X23, align 8, !pc !7
  %9 = load i64, ptr @__anvill_reg_X24, align 8, !pc !7
  %10 = load i64, ptr @__anvill_reg_X25, align 8, !pc !7
  %11 = load i64, ptr @__anvill_reg_X26, align 8, !pc !7
  %12 = load i64, ptr @__anvill_reg_X27, align 8, !pc !7
  %13 = load i64, ptr @__anvill_reg_X28, align 8, !pc !7
  %14 = load i64, ptr @__anvill_reg_X29, align 8, !pc !7
  %15 = load i8, ptr @__anvill_reg_V8, align 1, !pc !7
  %16 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 1), align 1, !pc !7
  %17 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 2), align 1, !pc !7
  %18 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 3), align 1, !pc !7
  %19 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 4), align 1, !pc !7
  %20 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 5), align 1, !pc !7
  %21 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 6), align 1, !pc !7
  %22 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 7), align 1, !pc !7
  %.sroa.139.144.insert.ext = zext i8 %15 to i64, !pc !7
  %.sroa.139.145.insert.ext = zext i8 %16 to i64, !pc !7
  %.sroa.139.145.insert.shift = shl nuw nsw i64 %.sroa.139.145.insert.ext, 8, !pc !7
  %.sroa.139.145.insert.insert = or i64 %.sroa.139.145.insert.shift, %.sroa.139.144.insert.ext, !pc !7
  %.sroa.139.146.insert.ext = zext i8 %17 to i64, !pc !7
  %.sroa.139.146.insert.shift = shl nuw nsw i64 %.sroa.139.146.insert.ext, 16, !pc !7
  %.sroa.139.146.insert.insert = or i64 %.sroa.139.145.insert.insert, %.sroa.139.146.insert.shift, !pc !7
  %.sroa.139.147.insert.ext = zext i8 %18 to i64, !pc !7
  %.sroa.139.147.insert.shift = shl nuw nsw i64 %.sroa.139.147.insert.ext, 24, !pc !7
  %.sroa.139.147.insert.insert = or i64 %.sroa.139.146.insert.insert, %.sroa.139.147.insert.shift, !pc !7
  %.sroa.139.148.insert.ext = zext i8 %19 to i64, !pc !7
  %.sroa.139.148.insert.shift = shl nuw nsw i64 %.sroa.139.148.insert.ext, 32, !pc !7
  %.sroa.139.149.insert.ext = zext i8 %20 to i64, !pc !7
  %.sroa.139.149.insert.shift = shl nuw nsw i64 %.sroa.139.149.insert.ext, 40, !pc !7
  %.sroa.139.149.insert.mask = or i64 %.sroa.139.147.insert.insert, %.sroa.139.148.insert.shift, !pc !7
  %.sroa.139.150.insert.ext = zext i8 %21 to i64, !pc !7
  %.sroa.139.150.insert.shift = shl nuw nsw i64 %.sroa.139.150.insert.ext, 48, !pc !7
  %.sroa.139.151.insert.ext = zext i8 %22 to i64, !pc !7
  %.sroa.139.151.insert.shift = shl nuw i64 %.sroa.139.151.insert.ext, 56, !pc !7
  %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.149.insert.mask, %.sroa.139.149.insert.shift, !pc !7
  %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.150.insert.shift, !pc !7
  %.sroa.139.159.insert.mask = or i64 %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.151.insert.shift, !pc !7
  %23 = load i8, ptr @__anvill_reg_V9, align 1, !pc !7
  %24 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 1), align 1, !pc !7
  %25 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 2), align 1, !pc !7
  %26 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 3), align 1, !pc !7
  %27 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 4), align 1, !pc !7
  %28 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 5), align 1, !pc !7
  %29 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 6), align 1, !pc !7
  %30 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 7), align 1, !pc !7
  %.sroa.157.160.insert.ext = zext i8 %23 to i64, !pc !7
  %.sroa.157.161.insert.ext = zext i8 %24 to i64, !pc !7
  %.sroa.157.161.insert.shift = shl nuw nsw i64 %.sroa.157.161.insert.ext, 8, !pc !7
  %.sroa.157.161.insert.insert = or i64 %.sroa.157.161.insert.shift, %.sroa.157.160.insert.ext, !pc !7
  %.sroa.157.162.insert.ext = zext i8 %25 to i64, !pc !7
  %.sroa.157.162.insert.shift = shl nuw nsw i64 %.sroa.157.162.insert.ext, 16, !pc !7
  %.sroa.157.162.insert.insert = or i64 %.sroa.157.161.insert.insert, %.sroa.157.162.insert.shift, !pc !7
  %.sroa.157.163.insert.ext = zext i8 %26 to i64, !pc !7
  %.sroa.157.163.insert.shift = shl nuw nsw i64 %.sroa.157.163.insert.ext, 24, !pc !7
  %.sroa.157.163.insert.insert = or i64 %.sroa.157.162.insert.insert, %.sroa.157.163.insert.shift, !pc !7
  %.sroa.157.164.insert.ext = zext i8 %27 to i64, !pc !7
  %.sroa.157.164.insert.shift = shl nuw nsw i64 %.sroa.157.164.insert.ext, 32, !pc !7
  %.sroa.157.165.insert.ext = zext i8 %28 to i64, !pc !7
  %.sroa.157.165.insert.shift = shl nuw nsw i64 %.sroa.157.165.insert.ext, 40, !pc !7
  %.sroa.157.165.insert.mask = or i64 %.sroa.157.163.insert.insert, %.sroa.157.164.insert.shift, !pc !7
  %.sroa.157.166.insert.ext = zext i8 %29 to i64, !pc !7
  %.sroa.157.166.insert.shift = shl nuw nsw i64 %.sroa.157.166.insert.ext, 48, !pc !7
  %.sroa.157.167.insert.ext = zext i8 %30 to i64, !pc !7
  %.sroa.157.167.insert.shift = shl nuw i64 %.sroa.157.167.insert.ext, 56, !pc !7
  %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.165.insert.mask, %.sroa.157.165.insert.shift, !pc !7
  %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.166.insert.shift, !pc !7
  %.sroa.157.175.insert.mask = or i64 %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.167.insert.shift, !pc !7
  %31 = load i8, ptr @__anvill_reg_V10, align 1, !pc !7
  %32 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 1), align 1, !pc !7
  %33 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 2), align 1, !pc !7
  %34 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 3), align 1, !pc !7
  %35 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 4), align 1, !pc !7
  %36 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 5), align 1, !pc !7
  %37 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 6), align 1, !pc !7
  %38 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 7), align 1, !pc !7
  %.sroa.175.176.insert.ext = zext i8 %31 to i64, !pc !7
  %.sroa.175.177.insert.ext = zext i8 %32 to i64, !pc !7
  %.sroa.175.177.insert.shift = shl nuw nsw i64 %.sroa.175.177.insert.ext, 8, !pc !7
  %.sroa.175.177.insert.insert = or i64 %.sroa.175.177.insert.shift, %.sroa.175.176.insert.ext, !pc !7
  %.sroa.175.178.insert.ext = zext i8 %33 to i64, !pc !7
  %.sroa.175.178.insert.shift = shl nuw nsw i64 %.sroa.175.178.insert.ext, 16, !pc !7
  %.sroa.175.178.insert.insert = or i64 %.sroa.175.177.insert.insert, %.sroa.175.178.insert.shift, !pc !7
  %.sroa.175.179.insert.ext = zext i8 %34 to i64, !pc !7
  %.sroa.175.179.insert.shift = shl nuw nsw i64 %.sroa.175.179.insert.ext, 24, !pc !7
  %.sroa.175.179.insert.insert = or i64 %.sroa.175.178.insert.insert, %.sroa.175.179.insert.shift, !pc !7
  %.sroa.175.180.insert.ext = zext i8 %35 to i64, !pc !7
  %.sroa.175.180.insert.shift = shl nuw nsw i64 %.sroa.175.180.insert.ext, 32, !pc !7
  %.sroa.175.181.insert.ext = zext i8 %36 to i64, !pc !7
  %.sroa.175.181.insert.shift = shl nuw nsw i64 %.sroa.175.181.insert.ext, 40, !pc !7
  %.sroa.175.181.insert.mask = or i64 %.sroa.175.179.insert.insert, %.sroa.175.180.insert.shift, !pc !7
  %.sroa.175.182.insert.ext = zext i8 %37 to i64, !pc !7
  %.sroa.175.182.insert.shift = shl nuw nsw i64 %.sroa.175.182.insert.ext, 48, !pc !7
  %.sroa.175.183.insert.ext = zext i8 %38 to i64, !pc !7
  %.sroa.175.183.insert.shift = shl nuw i64 %.sroa.175.183.insert.ext, 56, !pc !7
  %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.181.insert.mask, %.sroa.175.181.insert.shift, !pc !7
  %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.182.insert.shift, !pc !7
  %.sroa.175.191.insert.mask = or i64 %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.183.insert.shift, !pc !7
  %39 = load i8, ptr @__anvill_reg_V11, align 1, !pc !7
  %40 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 1), align 1, !pc !7
  %41 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 2), align 1, !pc !7
  %42 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 3), align 1, !pc !7
  %43 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 4), align 1, !pc !7
  %44 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 5), align 1, !pc !7
  %45 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 6), align 1, !pc !7
  %46 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 7), align 1, !pc !7
  %.sroa.193.192.insert.ext = zext i8 %39 to i64, !pc !7
  %.sroa.193.193.insert.ext = zext i8 %40 to i64, !pc !7
  %.sroa.193.193.insert.shift = shl nuw nsw i64 %.sroa.193.193.insert.ext, 8, !pc !7
  %.sroa.193.193.insert.insert = or i64 %.sroa.193.193.insert.shift, %.sroa.193.192.insert.ext, !pc !7
  %.sroa.193.194.insert.ext = zext i8 %41 to i64, !pc !7
  %.sroa.193.194.insert.shift = shl nuw nsw i64 %.sroa.193.194.insert.ext, 16, !pc !7
  %.sroa.193.194.insert.insert = or i64 %.sroa.193.193.insert.insert, %.sroa.193.194.insert.shift, !pc !7
  %.sroa.193.195.insert.ext = zext i8 %42 to i64, !pc !7
  %.sroa.193.195.insert.shift = shl nuw nsw i64 %.sroa.193.195.insert.ext, 24, !pc !7
  %.sroa.193.195.insert.insert = or i64 %.sroa.193.194.insert.insert, %.sroa.193.195.insert.shift, !pc !7
  %.sroa.193.196.insert.ext = zext i8 %43 to i64, !pc !7
  %.sroa.193.196.insert.shift = shl nuw nsw i64 %.sroa.193.196.insert.ext, 32, !pc !7
  %.sroa.193.197.insert.ext = zext i8 %44 to i64, !pc !7
  %.sroa.193.197.insert.shift = shl nuw nsw i64 %.sroa.193.197.insert.ext, 40, !pc !7
  %.sroa.193.197.insert.mask = or i64 %.sroa.193.195.insert.insert, %.sroa.193.196.insert.shift, !pc !7
  %.sroa.193.198.insert.ext = zext i8 %45 to i64, !pc !7
  %.sroa.193.198.insert.shift = shl nuw nsw i64 %.sroa.193.198.insert.ext, 48, !pc !7
  %.sroa.193.199.insert.ext = zext i8 %46 to i64, !pc !7
  %.sroa.193.199.insert.shift = shl nuw i64 %.sroa.193.199.insert.ext, 56, !pc !7
  %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.197.insert.mask, %.sroa.193.197.insert.shift, !pc !7
  %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.198.insert.shift, !pc !7
  %.sroa.193.207.insert.mask = or i64 %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.199.insert.shift, !pc !7
  %47 = load i8, ptr @__anvill_reg_V12, align 1, !pc !7
  %48 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 1), align 1, !pc !7
  %49 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 2), align 1, !pc !7
  %50 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 3), align 1, !pc !7
  %51 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 4), align 1, !pc !7
  %52 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 5), align 1, !pc !7
  %53 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 6), align 1, !pc !7
  %54 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 7), align 1, !pc !7
  %.sroa.211.208.insert.ext = zext i8 %47 to i64, !pc !7
  %.sroa.211.209.insert.ext = zext i8 %48 to i64, !pc !7
  %.sroa.211.209.insert.shift = shl nuw nsw i64 %.sroa.211.209.insert.ext, 8, !pc !7
  %.sroa.211.209.insert.insert = or i64 %.sroa.211.209.insert.shift, %.sroa.211.208.insert.ext, !pc !7
  %.sroa.211.210.insert.ext = zext i8 %49 to i64, !pc !7
  %.sroa.211.210.insert.shift = shl nuw nsw i64 %.sroa.211.210.insert.ext, 16, !pc !7
  %.sroa.211.210.insert.insert = or i64 %.sroa.211.209.insert.insert, %.sroa.211.210.insert.shift, !pc !7
  %.sroa.211.211.insert.ext = zext i8 %50 to i64, !pc !7
  %.sroa.211.211.insert.shift = shl nuw nsw i64 %.sroa.211.211.insert.ext, 24, !pc !7
  %.sroa.211.211.insert.insert = or i64 %.sroa.211.210.insert.insert, %.sroa.211.211.insert.shift, !pc !7
  %.sroa.211.212.insert.ext = zext i8 %51 to i64, !pc !7
  %.sroa.211.212.insert.shift = shl nuw nsw i64 %.sroa.211.212.insert.ext, 32, !pc !7
  %.sroa.211.213.insert.ext = zext i8 %52 to i64, !pc !7
  %.sroa.211.213.insert.shift = shl nuw nsw i64 %.sroa.211.213.insert.ext, 40, !pc !7
  %.sroa.211.213.insert.mask = or i64 %.sroa.211.211.insert.insert, %.sroa.211.212.insert.shift, !pc !7
  %.sroa.211.214.insert.ext = zext i8 %53 to i64, !pc !7
  %.sroa.211.214.insert.shift = shl nuw nsw i64 %.sroa.211.214.insert.ext, 48, !pc !7
  %.sroa.211.215.insert.ext = zext i8 %54 to i64, !pc !7
  %.sroa.211.215.insert.shift = shl nuw i64 %.sroa.211.215.insert.ext, 56, !pc !7
  %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.213.insert.mask, %.sroa.211.213.insert.shift, !pc !7
  %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.214.insert.shift, !pc !7
  %.sroa.211.223.insert.mask = or i64 %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.215.insert.shift, !pc !7
  %55 = load i8, ptr @__anvill_reg_V13, align 1, !pc !7
  %56 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 1), align 1, !pc !7
  %57 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 2), align 1, !pc !7
  %58 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 3), align 1, !pc !7
  %59 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 4), align 1, !pc !7
  %60 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 5), align 1, !pc !7
  %61 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 6), align 1, !pc !7
  %62 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 7), align 1, !pc !7
  %.sroa.229.224.insert.ext = zext i8 %55 to i64, !pc !7
  %.sroa.229.225.insert.ext = zext i8 %56 to i64, !pc !7
  %.sroa.229.225.insert.shift = shl nuw nsw i64 %.sroa.229.225.insert.ext, 8, !pc !7
  %.sroa.229.225.insert.insert = or i64 %.sroa.229.225.insert.shift, %.sroa.229.224.insert.ext, !pc !7
  %.sroa.229.226.insert.ext = zext i8 %57 to i64, !pc !7
  %.sroa.229.226.insert.shift = shl nuw nsw i64 %.sroa.229.226.insert.ext, 16, !pc !7
  %.sroa.229.226.insert.insert = or i64 %.sroa.229.225.insert.insert, %.sroa.229.226.insert.shift, !pc !7
  %.sroa.229.227.insert.ext = zext i8 %58 to i64, !pc !7
  %.sroa.229.227.insert.shift = shl nuw nsw i64 %.sroa.229.227.insert.ext, 24, !pc !7
  %.sroa.229.227.insert.insert = or i64 %.sroa.229.226.insert.insert, %.sroa.229.227.insert.shift, !pc !7
  %.sroa.229.228.insert.ext = zext i8 %59 to i64, !pc !7
  %.sroa.229.228.insert.shift = shl nuw nsw i64 %.sroa.229.228.insert.ext, 32, !pc !7
  %.sroa.229.229.insert.ext = zext i8 %60 to i64, !pc !7
  %.sroa.229.229.insert.shift = shl nuw nsw i64 %.sroa.229.229.insert.ext, 40, !pc !7
  %.sroa.229.229.insert.mask = or i64 %.sroa.229.227.insert.insert, %.sroa.229.228.insert.shift, !pc !7
  %.sroa.229.230.insert.ext = zext i8 %61 to i64, !pc !7
  %.sroa.229.230.insert.shift = shl nuw nsw i64 %.sroa.229.230.insert.ext, 48, !pc !7
  %.sroa.229.231.insert.ext = zext i8 %62 to i64, !pc !7
  %.sroa.229.231.insert.shift = shl nuw i64 %.sroa.229.231.insert.ext, 56, !pc !7
  %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.229.insert.mask, %.sroa.229.229.insert.shift, !pc !7
  %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.230.insert.shift, !pc !7
  %.sroa.229.239.insert.mask = or i64 %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.231.insert.shift, !pc !7
  %63 = load i8, ptr @__anvill_reg_V14, align 1, !pc !7
  %64 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 1), align 1, !pc !7
  %65 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 2), align 1, !pc !7
  %66 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 3), align 1, !pc !7
  %67 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 4), align 1, !pc !7
  %68 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 5), align 1, !pc !7
  %69 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 6), align 1, !pc !7
  %70 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 7), align 1, !pc !7
  %.sroa.247.240.insert.ext = zext i8 %63 to i64, !pc !7
  %.sroa.247.241.insert.ext = zext i8 %64 to i64, !pc !7
  %.sroa.247.241.insert.shift = shl nuw nsw i64 %.sroa.247.241.insert.ext, 8, !pc !7
  %.sroa.247.241.insert.insert = or i64 %.sroa.247.241.insert.shift, %.sroa.247.240.insert.ext, !pc !7
  %.sroa.247.242.insert.ext = zext i8 %65 to i64, !pc !7
  %.sroa.247.242.insert.shift = shl nuw nsw i64 %.sroa.247.242.insert.ext, 16, !pc !7
  %.sroa.247.242.insert.insert = or i64 %.sroa.247.241.insert.insert, %.sroa.247.242.insert.shift, !pc !7
  %.sroa.247.243.insert.ext = zext i8 %66 to i64, !pc !7
  %.sroa.247.243.insert.shift = shl nuw nsw i64 %.sroa.247.243.insert.ext, 24, !pc !7
  %.sroa.247.243.insert.insert = or i64 %.sroa.247.242.insert.insert, %.sroa.247.243.insert.shift, !pc !7
  %.sroa.247.244.insert.ext = zext i8 %67 to i64, !pc !7
  %.sroa.247.244.insert.shift = shl nuw nsw i64 %.sroa.247.244.insert.ext, 32, !pc !7
  %.sroa.247.245.insert.ext = zext i8 %68 to i64, !pc !7
  %.sroa.247.245.insert.shift = shl nuw nsw i64 %.sroa.247.245.insert.ext, 40, !pc !7
  %.sroa.247.245.insert.mask = or i64 %.sroa.247.243.insert.insert, %.sroa.247.244.insert.shift, !pc !7
  %.sroa.247.246.insert.ext = zext i8 %69 to i64, !pc !7
  %.sroa.247.246.insert.shift = shl nuw nsw i64 %.sroa.247.246.insert.ext, 48, !pc !7
  %.sroa.247.247.insert.ext = zext i8 %70 to i64, !pc !7
  %.sroa.247.247.insert.shift = shl nuw i64 %.sroa.247.247.insert.ext, 56, !pc !7
  %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.245.insert.mask, %.sroa.247.245.insert.shift, !pc !7
  %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.246.insert.shift, !pc !7
  %.sroa.247.255.insert.mask = or i64 %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.247.insert.shift, !pc !7
  %71 = load i8, ptr @__anvill_reg_V15, align 1, !pc !7
  %72 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 1), align 1, !pc !7
  %73 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 2), align 1, !pc !7
  %74 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 3), align 1, !pc !7
  %75 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 4), align 1, !pc !7
  %76 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 5), align 1, !pc !7
  %77 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 6), align 1, !pc !7
  %78 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 7), align 1, !pc !7
  %.sroa.265.256.insert.ext = zext i8 %71 to i64, !pc !7
  %.sroa.265.257.insert.ext = zext i8 %72 to i64, !pc !7
  %.sroa.265.257.insert.shift = shl nuw nsw i64 %.sroa.265.257.insert.ext, 8, !pc !7
  %.sroa.265.257.insert.insert = or i64 %.sroa.265.257.insert.shift, %.sroa.265.256.insert.ext, !pc !7
  %.sroa.265.258.insert.ext = zext i8 %73 to i64, !pc !7
  %.sroa.265.258.insert.shift = shl nuw nsw i64 %.sroa.265.258.insert.ext, 16, !pc !7
  %.sroa.265.258.insert.insert = or i64 %.sroa.265.257.insert.insert, %.sroa.265.258.insert.shift, !pc !7
  %.sroa.265.259.insert.ext = zext i8 %74 to i64, !pc !7
  %.sroa.265.259.insert.shift = shl nuw nsw i64 %.sroa.265.259.insert.ext, 24, !pc !7
  %.sroa.265.259.insert.insert = or i64 %.sroa.265.258.insert.insert, %.sroa.265.259.insert.shift, !pc !7
  %.sroa.265.260.insert.ext = zext i8 %75 to i64, !pc !7
  %.sroa.265.260.insert.shift = shl nuw nsw i64 %.sroa.265.260.insert.ext, 32, !pc !7
  %.sroa.265.261.insert.ext = zext i8 %76 to i64, !pc !7
  %.sroa.265.261.insert.shift = shl nuw nsw i64 %.sroa.265.261.insert.ext, 40, !pc !7
  %.sroa.265.261.insert.mask = or i64 %.sroa.265.259.insert.insert, %.sroa.265.260.insert.shift, !pc !7
  %.sroa.265.262.insert.ext = zext i8 %77 to i64, !pc !7
  %.sroa.265.262.insert.shift = shl nuw nsw i64 %.sroa.265.262.insert.ext, 48, !pc !7
  %.sroa.265.263.insert.ext = zext i8 %78 to i64, !pc !7
  %.sroa.265.263.insert.shift = shl nuw i64 %.sroa.265.263.insert.ext, 56, !pc !7
  %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.261.insert.mask, %.sroa.265.261.insert.shift, !pc !7
  %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.262.insert.shift, !pc !7
  %.sroa.265.271.insert.mask = or i64 %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.263.insert.shift, !pc !7
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %2), !pc !7
  call void @llvm.lifetime.start.p0(i64 0, ptr nonnull %1), !pc !7
  call void @llvm.lifetime.start.p0(i64 160, ptr nonnull %3), !pc !7
  store i64 ptrtoint (ptr @sub_100003f5c__Avv_B_0 to i64), ptr %2, align 8, !pc !7
  store i64 %9, ptr %3, align 8, !pc !7
  %79 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 1, !pc !7
  store i64 %7, ptr %79, align 8, !pc !7
  %80 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 2, !pc !7
  store i64 %5, ptr %80, align 8, !pc !7
  %81 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 3, !pc !7
  store i64 %10, ptr %81, align 8, !pc !7
  %82 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 4, !pc !7
  store i64 %13, ptr %82, align 8, !pc !7
  %83 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 5, !pc !7
  store i64 %8, ptr %83, align 8, !pc !7
  %84 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 6, !pc !7
  store i64 %6, ptr %84, align 8, !pc !7
  %85 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 7, !pc !7
  store i64 %.sroa.229.239.insert.mask, ptr %85, align 8, !pc !7
  %86 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 8, !pc !7
  store i64 %.sroa.157.175.insert.mask, ptr %86, align 8, !pc !7
  %87 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 9, !pc !7
  store i64 %.sroa.211.223.insert.mask, ptr %87, align 8, !pc !7
  %88 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 10, !pc !7
  store i64 %11, ptr %88, align 8, !pc !7
  %89 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 11, !pc !7
  store i64 %14, ptr %89, align 8, !pc !7
  %90 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 12, !pc !7
  store i64 %.sroa.247.255.insert.mask, ptr %90, align 8, !pc !7
  %91 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 13, !pc !7
  store i64 ptrtoint (ptr @__anvill_ra to i64), ptr %91, align 8, !pc !7
  %92 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 14, !pc !7
  store i64 %4, ptr %92, align 8, !pc !7
  %93 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 15, !pc !7
  store i64 %.sroa.139.159.insert.mask, ptr %93, align 8, !pc !7
  %94 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 16, !pc !7
  store i64 %.sroa.193.207.insert.mask, ptr %94, align 8, !pc !7
  %95 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 17, !pc !7
  store i64 %.sroa.265.271.insert.mask, ptr %95, align 8, !pc !7
  %96 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 18, !pc !7
  store i64 %.sroa.175.191.insert.mask, ptr %96, align 8, !pc !7
  %97 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 19, !pc !7
  store i64 %12, ptr %97, align 8, !pc !7
  %98 = call ptr @basic_block_func4294983516(ptr nonnull %1, i64 ptrtoint (ptr @sub_100003f5c__Avv_B_0 to i64), ptr null, ptr nonnull %2, ptr nonnull %3, ptr nonnull %79, ptr nonnull %80, ptr nonnull %81, ptr nonnull %82, ptr nonnull %83, ptr nonnull %84, ptr nonnull %85, ptr nonnull %86, ptr nonnull %87, ptr nonnull %88, ptr nonnull %89, ptr nonnull %90, ptr nonnull %91, ptr nonnull %92, ptr nonnull %93, ptr nonnull %94, ptr nonnull %95, ptr nonnull %96, ptr nonnull %97) #12, !pc !7
  unreachable, !pc !7
}

; Function Attrs: noinline
define ptr @basic_block_func4294983536(ptr noalias %stack, i64 %program_counter, ptr %memory, ptr %next_pc_out, ptr noalias %X24, ptr noalias %X22, ptr noalias %X20, ptr noalias %X28, ptr noalias %X23, ptr noalias %X21, ptr noalias %D13, ptr noalias %D9, ptr noalias %D12, ptr noalias %X26, ptr noalias %X29, ptr noalias %D14, ptr noalias %X30, ptr noalias %X19, ptr noalias %D8, ptr noalias %i, ptr noalias %X25, ptr noalias %D11, ptr noalias %D15, ptr noalias %D10, ptr noalias %X27) local_unnamed_addr #9 !__anvill_basic_block_md !8 {
  %1 = load i32, ptr %i, align 4
  store i32 %1, ptr %stack, align 4
  %2 = sext i32 %1 to i64
  %3 = shl nsw i64 %2, 2
  %4 = add i64 %3, 4294983700
  %5 = inttoptr i64 %4 to ptr
  %6 = load i32, ptr %5, align 4
  store i32 %6, ptr inttoptr (i64 4294983696 to ptr), align 16
  call void (...) @__anvill_basic_block_function_return()
  ret ptr %memory
}

; Function Attrs: noinline
define void @sub_100003f70__AIv_B_0(i32 %0) local_unnamed_addr #9 !pc !8 {
  %2 = alloca i64, align 8, !pc !8
  %3 = alloca [16 x i8], align 4, !pc !8
  %4 = alloca <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, align 8, !pc !8
  %5 = load i64, ptr @__anvill_reg_X19, align 8, !pc !8
  %6 = load i64, ptr @__anvill_reg_X20, align 8, !pc !8
  %7 = load i64, ptr @__anvill_reg_X21, align 8, !pc !8
  %8 = load i64, ptr @__anvill_reg_X22, align 8, !pc !8
  %9 = load i64, ptr @__anvill_reg_X23, align 8, !pc !8
  %10 = load i64, ptr @__anvill_reg_X24, align 8, !pc !8
  %11 = load i64, ptr @__anvill_reg_X25, align 8, !pc !8
  %12 = load i64, ptr @__anvill_reg_X26, align 8, !pc !8
  %13 = load i64, ptr @__anvill_reg_X27, align 8, !pc !8
  %14 = load i64, ptr @__anvill_reg_X28, align 8, !pc !8
  %15 = load i64, ptr @__anvill_reg_X29, align 8, !pc !8
  %16 = load i8, ptr @__anvill_reg_V8, align 1, !pc !8
  %17 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 1), align 1, !pc !8
  %18 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 2), align 1, !pc !8
  %19 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 3), align 1, !pc !8
  %20 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 4), align 1, !pc !8
  %21 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 5), align 1, !pc !8
  %22 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 6), align 1, !pc !8
  %23 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 7), align 1, !pc !8
  %.sroa.139.144.insert.ext = zext i8 %16 to i64, !pc !8
  %.sroa.139.145.insert.ext = zext i8 %17 to i64, !pc !8
  %.sroa.139.145.insert.shift = shl nuw nsw i64 %.sroa.139.145.insert.ext, 8, !pc !8
  %.sroa.139.145.insert.insert = or i64 %.sroa.139.145.insert.shift, %.sroa.139.144.insert.ext, !pc !8
  %.sroa.139.146.insert.ext = zext i8 %18 to i64, !pc !8
  %.sroa.139.146.insert.shift = shl nuw nsw i64 %.sroa.139.146.insert.ext, 16, !pc !8
  %.sroa.139.146.insert.insert = or i64 %.sroa.139.145.insert.insert, %.sroa.139.146.insert.shift, !pc !8
  %.sroa.139.147.insert.ext = zext i8 %19 to i64, !pc !8
  %.sroa.139.147.insert.shift = shl nuw nsw i64 %.sroa.139.147.insert.ext, 24, !pc !8
  %.sroa.139.147.insert.insert = or i64 %.sroa.139.146.insert.insert, %.sroa.139.147.insert.shift, !pc !8
  %.sroa.139.148.insert.ext = zext i8 %20 to i64, !pc !8
  %.sroa.139.148.insert.shift = shl nuw nsw i64 %.sroa.139.148.insert.ext, 32, !pc !8
  %.sroa.139.149.insert.ext = zext i8 %21 to i64, !pc !8
  %.sroa.139.149.insert.shift = shl nuw nsw i64 %.sroa.139.149.insert.ext, 40, !pc !8
  %.sroa.139.149.insert.mask = or i64 %.sroa.139.147.insert.insert, %.sroa.139.148.insert.shift, !pc !8
  %.sroa.139.150.insert.ext = zext i8 %22 to i64, !pc !8
  %.sroa.139.150.insert.shift = shl nuw nsw i64 %.sroa.139.150.insert.ext, 48, !pc !8
  %.sroa.139.151.insert.ext = zext i8 %23 to i64, !pc !8
  %.sroa.139.151.insert.shift = shl nuw i64 %.sroa.139.151.insert.ext, 56, !pc !8
  %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.149.insert.mask, %.sroa.139.149.insert.shift, !pc !8
  %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.150.insert.shift, !pc !8
  %.sroa.139.159.insert.mask = or i64 %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.151.insert.shift, !pc !8
  %24 = load i8, ptr @__anvill_reg_V9, align 1, !pc !8
  %25 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 1), align 1, !pc !8
  %26 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 2), align 1, !pc !8
  %27 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 3), align 1, !pc !8
  %28 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 4), align 1, !pc !8
  %29 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 5), align 1, !pc !8
  %30 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 6), align 1, !pc !8
  %31 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 7), align 1, !pc !8
  %.sroa.157.160.insert.ext = zext i8 %24 to i64, !pc !8
  %.sroa.157.161.insert.ext = zext i8 %25 to i64, !pc !8
  %.sroa.157.161.insert.shift = shl nuw nsw i64 %.sroa.157.161.insert.ext, 8, !pc !8
  %.sroa.157.161.insert.insert = or i64 %.sroa.157.161.insert.shift, %.sroa.157.160.insert.ext, !pc !8
  %.sroa.157.162.insert.ext = zext i8 %26 to i64, !pc !8
  %.sroa.157.162.insert.shift = shl nuw nsw i64 %.sroa.157.162.insert.ext, 16, !pc !8
  %.sroa.157.162.insert.insert = or i64 %.sroa.157.161.insert.insert, %.sroa.157.162.insert.shift, !pc !8
  %.sroa.157.163.insert.ext = zext i8 %27 to i64, !pc !8
  %.sroa.157.163.insert.shift = shl nuw nsw i64 %.sroa.157.163.insert.ext, 24, !pc !8
  %.sroa.157.163.insert.insert = or i64 %.sroa.157.162.insert.insert, %.sroa.157.163.insert.shift, !pc !8
  %.sroa.157.164.insert.ext = zext i8 %28 to i64, !pc !8
  %.sroa.157.164.insert.shift = shl nuw nsw i64 %.sroa.157.164.insert.ext, 32, !pc !8
  %.sroa.157.165.insert.ext = zext i8 %29 to i64, !pc !8
  %.sroa.157.165.insert.shift = shl nuw nsw i64 %.sroa.157.165.insert.ext, 40, !pc !8
  %.sroa.157.165.insert.mask = or i64 %.sroa.157.163.insert.insert, %.sroa.157.164.insert.shift, !pc !8
  %.sroa.157.166.insert.ext = zext i8 %30 to i64, !pc !8
  %.sroa.157.166.insert.shift = shl nuw nsw i64 %.sroa.157.166.insert.ext, 48, !pc !8
  %.sroa.157.167.insert.ext = zext i8 %31 to i64, !pc !8
  %.sroa.157.167.insert.shift = shl nuw i64 %.sroa.157.167.insert.ext, 56, !pc !8
  %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.165.insert.mask, %.sroa.157.165.insert.shift, !pc !8
  %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.166.insert.shift, !pc !8
  %.sroa.157.175.insert.mask = or i64 %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.167.insert.shift, !pc !8
  %32 = load i8, ptr @__anvill_reg_V10, align 1, !pc !8
  %33 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 1), align 1, !pc !8
  %34 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 2), align 1, !pc !8
  %35 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 3), align 1, !pc !8
  %36 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 4), align 1, !pc !8
  %37 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 5), align 1, !pc !8
  %38 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 6), align 1, !pc !8
  %39 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 7), align 1, !pc !8
  %.sroa.175.176.insert.ext = zext i8 %32 to i64, !pc !8
  %.sroa.175.177.insert.ext = zext i8 %33 to i64, !pc !8
  %.sroa.175.177.insert.shift = shl nuw nsw i64 %.sroa.175.177.insert.ext, 8, !pc !8
  %.sroa.175.177.insert.insert = or i64 %.sroa.175.177.insert.shift, %.sroa.175.176.insert.ext, !pc !8
  %.sroa.175.178.insert.ext = zext i8 %34 to i64, !pc !8
  %.sroa.175.178.insert.shift = shl nuw nsw i64 %.sroa.175.178.insert.ext, 16, !pc !8
  %.sroa.175.178.insert.insert = or i64 %.sroa.175.177.insert.insert, %.sroa.175.178.insert.shift, !pc !8
  %.sroa.175.179.insert.ext = zext i8 %35 to i64, !pc !8
  %.sroa.175.179.insert.shift = shl nuw nsw i64 %.sroa.175.179.insert.ext, 24, !pc !8
  %.sroa.175.179.insert.insert = or i64 %.sroa.175.178.insert.insert, %.sroa.175.179.insert.shift, !pc !8
  %.sroa.175.180.insert.ext = zext i8 %36 to i64, !pc !8
  %.sroa.175.180.insert.shift = shl nuw nsw i64 %.sroa.175.180.insert.ext, 32, !pc !8
  %.sroa.175.181.insert.ext = zext i8 %37 to i64, !pc !8
  %.sroa.175.181.insert.shift = shl nuw nsw i64 %.sroa.175.181.insert.ext, 40, !pc !8
  %.sroa.175.181.insert.mask = or i64 %.sroa.175.179.insert.insert, %.sroa.175.180.insert.shift, !pc !8
  %.sroa.175.182.insert.ext = zext i8 %38 to i64, !pc !8
  %.sroa.175.182.insert.shift = shl nuw nsw i64 %.sroa.175.182.insert.ext, 48, !pc !8
  %.sroa.175.183.insert.ext = zext i8 %39 to i64, !pc !8
  %.sroa.175.183.insert.shift = shl nuw i64 %.sroa.175.183.insert.ext, 56, !pc !8
  %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.181.insert.mask, %.sroa.175.181.insert.shift, !pc !8
  %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.182.insert.shift, !pc !8
  %.sroa.175.191.insert.mask = or i64 %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.183.insert.shift, !pc !8
  %40 = load i8, ptr @__anvill_reg_V11, align 1, !pc !8
  %41 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 1), align 1, !pc !8
  %42 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 2), align 1, !pc !8
  %43 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 3), align 1, !pc !8
  %44 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 4), align 1, !pc !8
  %45 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 5), align 1, !pc !8
  %46 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 6), align 1, !pc !8
  %47 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 7), align 1, !pc !8
  %.sroa.193.192.insert.ext = zext i8 %40 to i64, !pc !8
  %.sroa.193.193.insert.ext = zext i8 %41 to i64, !pc !8
  %.sroa.193.193.insert.shift = shl nuw nsw i64 %.sroa.193.193.insert.ext, 8, !pc !8
  %.sroa.193.193.insert.insert = or i64 %.sroa.193.193.insert.shift, %.sroa.193.192.insert.ext, !pc !8
  %.sroa.193.194.insert.ext = zext i8 %42 to i64, !pc !8
  %.sroa.193.194.insert.shift = shl nuw nsw i64 %.sroa.193.194.insert.ext, 16, !pc !8
  %.sroa.193.194.insert.insert = or i64 %.sroa.193.193.insert.insert, %.sroa.193.194.insert.shift, !pc !8
  %.sroa.193.195.insert.ext = zext i8 %43 to i64, !pc !8
  %.sroa.193.195.insert.shift = shl nuw nsw i64 %.sroa.193.195.insert.ext, 24, !pc !8
  %.sroa.193.195.insert.insert = or i64 %.sroa.193.194.insert.insert, %.sroa.193.195.insert.shift, !pc !8
  %.sroa.193.196.insert.ext = zext i8 %44 to i64, !pc !8
  %.sroa.193.196.insert.shift = shl nuw nsw i64 %.sroa.193.196.insert.ext, 32, !pc !8
  %.sroa.193.197.insert.ext = zext i8 %45 to i64, !pc !8
  %.sroa.193.197.insert.shift = shl nuw nsw i64 %.sroa.193.197.insert.ext, 40, !pc !8
  %.sroa.193.197.insert.mask = or i64 %.sroa.193.195.insert.insert, %.sroa.193.196.insert.shift, !pc !8
  %.sroa.193.198.insert.ext = zext i8 %46 to i64, !pc !8
  %.sroa.193.198.insert.shift = shl nuw nsw i64 %.sroa.193.198.insert.ext, 48, !pc !8
  %.sroa.193.199.insert.ext = zext i8 %47 to i64, !pc !8
  %.sroa.193.199.insert.shift = shl nuw i64 %.sroa.193.199.insert.ext, 56, !pc !8
  %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.197.insert.mask, %.sroa.193.197.insert.shift, !pc !8
  %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.198.insert.shift, !pc !8
  %.sroa.193.207.insert.mask = or i64 %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.199.insert.shift, !pc !8
  %48 = load i8, ptr @__anvill_reg_V12, align 1, !pc !8
  %49 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 1), align 1, !pc !8
  %50 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 2), align 1, !pc !8
  %51 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 3), align 1, !pc !8
  %52 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 4), align 1, !pc !8
  %53 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 5), align 1, !pc !8
  %54 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 6), align 1, !pc !8
  %55 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 7), align 1, !pc !8
  %.sroa.211.208.insert.ext = zext i8 %48 to i64, !pc !8
  %.sroa.211.209.insert.ext = zext i8 %49 to i64, !pc !8
  %.sroa.211.209.insert.shift = shl nuw nsw i64 %.sroa.211.209.insert.ext, 8, !pc !8
  %.sroa.211.209.insert.insert = or i64 %.sroa.211.209.insert.shift, %.sroa.211.208.insert.ext, !pc !8
  %.sroa.211.210.insert.ext = zext i8 %50 to i64, !pc !8
  %.sroa.211.210.insert.shift = shl nuw nsw i64 %.sroa.211.210.insert.ext, 16, !pc !8
  %.sroa.211.210.insert.insert = or i64 %.sroa.211.209.insert.insert, %.sroa.211.210.insert.shift, !pc !8
  %.sroa.211.211.insert.ext = zext i8 %51 to i64, !pc !8
  %.sroa.211.211.insert.shift = shl nuw nsw i64 %.sroa.211.211.insert.ext, 24, !pc !8
  %.sroa.211.211.insert.insert = or i64 %.sroa.211.210.insert.insert, %.sroa.211.211.insert.shift, !pc !8
  %.sroa.211.212.insert.ext = zext i8 %52 to i64, !pc !8
  %.sroa.211.212.insert.shift = shl nuw nsw i64 %.sroa.211.212.insert.ext, 32, !pc !8
  %.sroa.211.213.insert.ext = zext i8 %53 to i64, !pc !8
  %.sroa.211.213.insert.shift = shl nuw nsw i64 %.sroa.211.213.insert.ext, 40, !pc !8
  %.sroa.211.213.insert.mask = or i64 %.sroa.211.211.insert.insert, %.sroa.211.212.insert.shift, !pc !8
  %.sroa.211.214.insert.ext = zext i8 %54 to i64, !pc !8
  %.sroa.211.214.insert.shift = shl nuw nsw i64 %.sroa.211.214.insert.ext, 48, !pc !8
  %.sroa.211.215.insert.ext = zext i8 %55 to i64, !pc !8
  %.sroa.211.215.insert.shift = shl nuw i64 %.sroa.211.215.insert.ext, 56, !pc !8
  %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.213.insert.mask, %.sroa.211.213.insert.shift, !pc !8
  %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.214.insert.shift, !pc !8
  %.sroa.211.223.insert.mask = or i64 %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.215.insert.shift, !pc !8
  %56 = load i8, ptr @__anvill_reg_V13, align 1, !pc !8
  %57 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 1), align 1, !pc !8
  %58 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 2), align 1, !pc !8
  %59 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 3), align 1, !pc !8
  %60 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 4), align 1, !pc !8
  %61 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 5), align 1, !pc !8
  %62 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 6), align 1, !pc !8
  %63 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 7), align 1, !pc !8
  %.sroa.229.224.insert.ext = zext i8 %56 to i64, !pc !8
  %.sroa.229.225.insert.ext = zext i8 %57 to i64, !pc !8
  %.sroa.229.225.insert.shift = shl nuw nsw i64 %.sroa.229.225.insert.ext, 8, !pc !8
  %.sroa.229.225.insert.insert = or i64 %.sroa.229.225.insert.shift, %.sroa.229.224.insert.ext, !pc !8
  %.sroa.229.226.insert.ext = zext i8 %58 to i64, !pc !8
  %.sroa.229.226.insert.shift = shl nuw nsw i64 %.sroa.229.226.insert.ext, 16, !pc !8
  %.sroa.229.226.insert.insert = or i64 %.sroa.229.225.insert.insert, %.sroa.229.226.insert.shift, !pc !8
  %.sroa.229.227.insert.ext = zext i8 %59 to i64, !pc !8
  %.sroa.229.227.insert.shift = shl nuw nsw i64 %.sroa.229.227.insert.ext, 24, !pc !8
  %.sroa.229.227.insert.insert = or i64 %.sroa.229.226.insert.insert, %.sroa.229.227.insert.shift, !pc !8
  %.sroa.229.228.insert.ext = zext i8 %60 to i64, !pc !8
  %.sroa.229.228.insert.shift = shl nuw nsw i64 %.sroa.229.228.insert.ext, 32, !pc !8
  %.sroa.229.229.insert.ext = zext i8 %61 to i64, !pc !8
  %.sroa.229.229.insert.shift = shl nuw nsw i64 %.sroa.229.229.insert.ext, 40, !pc !8
  %.sroa.229.229.insert.mask = or i64 %.sroa.229.227.insert.insert, %.sroa.229.228.insert.shift, !pc !8
  %.sroa.229.230.insert.ext = zext i8 %62 to i64, !pc !8
  %.sroa.229.230.insert.shift = shl nuw nsw i64 %.sroa.229.230.insert.ext, 48, !pc !8
  %.sroa.229.231.insert.ext = zext i8 %63 to i64, !pc !8
  %.sroa.229.231.insert.shift = shl nuw i64 %.sroa.229.231.insert.ext, 56, !pc !8
  %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.229.insert.mask, %.sroa.229.229.insert.shift, !pc !8
  %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.230.insert.shift, !pc !8
  %.sroa.229.239.insert.mask = or i64 %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.231.insert.shift, !pc !8
  %64 = load i8, ptr @__anvill_reg_V14, align 1, !pc !8
  %65 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 1), align 1, !pc !8
  %66 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 2), align 1, !pc !8
  %67 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 3), align 1, !pc !8
  %68 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 4), align 1, !pc !8
  %69 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 5), align 1, !pc !8
  %70 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 6), align 1, !pc !8
  %71 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 7), align 1, !pc !8
  %.sroa.247.240.insert.ext = zext i8 %64 to i64, !pc !8
  %.sroa.247.241.insert.ext = zext i8 %65 to i64, !pc !8
  %.sroa.247.241.insert.shift = shl nuw nsw i64 %.sroa.247.241.insert.ext, 8, !pc !8
  %.sroa.247.241.insert.insert = or i64 %.sroa.247.241.insert.shift, %.sroa.247.240.insert.ext, !pc !8
  %.sroa.247.242.insert.ext = zext i8 %66 to i64, !pc !8
  %.sroa.247.242.insert.shift = shl nuw nsw i64 %.sroa.247.242.insert.ext, 16, !pc !8
  %.sroa.247.242.insert.insert = or i64 %.sroa.247.241.insert.insert, %.sroa.247.242.insert.shift, !pc !8
  %.sroa.247.243.insert.ext = zext i8 %67 to i64, !pc !8
  %.sroa.247.243.insert.shift = shl nuw nsw i64 %.sroa.247.243.insert.ext, 24, !pc !8
  %.sroa.247.243.insert.insert = or i64 %.sroa.247.242.insert.insert, %.sroa.247.243.insert.shift, !pc !8
  %.sroa.247.244.insert.ext = zext i8 %68 to i64, !pc !8
  %.sroa.247.244.insert.shift = shl nuw nsw i64 %.sroa.247.244.insert.ext, 32, !pc !8
  %.sroa.247.245.insert.ext = zext i8 %69 to i64, !pc !8
  %.sroa.247.245.insert.shift = shl nuw nsw i64 %.sroa.247.245.insert.ext, 40, !pc !8
  %.sroa.247.245.insert.mask = or i64 %.sroa.247.243.insert.insert, %.sroa.247.244.insert.shift, !pc !8
  %.sroa.247.246.insert.ext = zext i8 %70 to i64, !pc !8
  %.sroa.247.246.insert.shift = shl nuw nsw i64 %.sroa.247.246.insert.ext, 48, !pc !8
  %.sroa.247.247.insert.ext = zext i8 %71 to i64, !pc !8
  %.sroa.247.247.insert.shift = shl nuw i64 %.sroa.247.247.insert.ext, 56, !pc !8
  %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.245.insert.mask, %.sroa.247.245.insert.shift, !pc !8
  %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.246.insert.shift, !pc !8
  %.sroa.247.255.insert.mask = or i64 %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.247.insert.shift, !pc !8
  %72 = load i8, ptr @__anvill_reg_V15, align 1, !pc !8
  %73 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 1), align 1, !pc !8
  %74 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 2), align 1, !pc !8
  %75 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 3), align 1, !pc !8
  %76 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 4), align 1, !pc !8
  %77 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 5), align 1, !pc !8
  %78 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 6), align 1, !pc !8
  %79 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 7), align 1, !pc !8
  %.sroa.265.256.insert.ext = zext i8 %72 to i64, !pc !8
  %.sroa.265.257.insert.ext = zext i8 %73 to i64, !pc !8
  %.sroa.265.257.insert.shift = shl nuw nsw i64 %.sroa.265.257.insert.ext, 8, !pc !8
  %.sroa.265.257.insert.insert = or i64 %.sroa.265.257.insert.shift, %.sroa.265.256.insert.ext, !pc !8
  %.sroa.265.258.insert.ext = zext i8 %74 to i64, !pc !8
  %.sroa.265.258.insert.shift = shl nuw nsw i64 %.sroa.265.258.insert.ext, 16, !pc !8
  %.sroa.265.258.insert.insert = or i64 %.sroa.265.257.insert.insert, %.sroa.265.258.insert.shift, !pc !8
  %.sroa.265.259.insert.ext = zext i8 %75 to i64, !pc !8
  %.sroa.265.259.insert.shift = shl nuw nsw i64 %.sroa.265.259.insert.ext, 24, !pc !8
  %.sroa.265.259.insert.insert = or i64 %.sroa.265.258.insert.insert, %.sroa.265.259.insert.shift, !pc !8
  %.sroa.265.260.insert.ext = zext i8 %76 to i64, !pc !8
  %.sroa.265.260.insert.shift = shl nuw nsw i64 %.sroa.265.260.insert.ext, 32, !pc !8
  %.sroa.265.261.insert.ext = zext i8 %77 to i64, !pc !8
  %.sroa.265.261.insert.shift = shl nuw nsw i64 %.sroa.265.261.insert.ext, 40, !pc !8
  %.sroa.265.261.insert.mask = or i64 %.sroa.265.259.insert.insert, %.sroa.265.260.insert.shift, !pc !8
  %.sroa.265.262.insert.ext = zext i8 %78 to i64, !pc !8
  %.sroa.265.262.insert.shift = shl nuw nsw i64 %.sroa.265.262.insert.ext, 48, !pc !8
  %.sroa.265.263.insert.ext = zext i8 %79 to i64, !pc !8
  %.sroa.265.263.insert.shift = shl nuw i64 %.sroa.265.263.insert.ext, 56, !pc !8
  %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.261.insert.mask, %.sroa.265.261.insert.shift, !pc !8
  %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.262.insert.shift, !pc !8
  %.sroa.265.271.insert.mask = or i64 %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.263.insert.shift, !pc !8
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %2), !pc !8
  call void @llvm.lifetime.start.p0(i64 16, ptr nonnull %3), !pc !8
  call void @llvm.lifetime.start.p0(i64 164, ptr nonnull %4), !pc !8
  store i64 ptrtoint (ptr @sub_100003f70__AIv_B_0 to i64), ptr %2, align 8, !pc !8
  store i64 %10, ptr %4, align 8, !pc !8
  %80 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 1, !pc !8
  store i64 %8, ptr %80, align 8, !pc !8
  %81 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 2, !pc !8
  store i64 %6, ptr %81, align 8, !pc !8
  %82 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 3, !pc !8
  store i64 %14, ptr %82, align 8, !pc !8
  %83 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 4, !pc !8
  store i64 %9, ptr %83, align 8, !pc !8
  %84 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 5, !pc !8
  store i64 %7, ptr %84, align 8, !pc !8
  %85 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 6, !pc !8
  store i64 %.sroa.229.239.insert.mask, ptr %85, align 8, !pc !8
  %86 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 7, !pc !8
  store i64 %.sroa.157.175.insert.mask, ptr %86, align 8, !pc !8
  %87 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 8, !pc !8
  store i64 %.sroa.211.223.insert.mask, ptr %87, align 8, !pc !8
  %88 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 9, !pc !8
  store i64 %12, ptr %88, align 8, !pc !8
  %89 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 10, !pc !8
  store i64 %15, ptr %89, align 8, !pc !8
  %90 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 11, !pc !8
  store i64 %.sroa.247.255.insert.mask, ptr %90, align 8, !pc !8
  %91 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 12, !pc !8
  store i64 ptrtoint (ptr @__anvill_ra to i64), ptr %91, align 8, !pc !8
  %92 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 13, !pc !8
  store i64 %5, ptr %92, align 8, !pc !8
  %93 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 14, !pc !8
  store i64 %.sroa.139.159.insert.mask, ptr %93, align 8, !pc !8
  %94 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 15, !pc !8
  store i32 %0, ptr %94, align 8, !pc !8
  %95 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 16, !pc !8
  store i64 %11, ptr %95, align 8, !pc !8
  %96 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 17, !pc !8
  store i64 %.sroa.193.207.insert.mask, ptr %96, align 8, !pc !8
  %97 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 18, !pc !8
  store i64 %.sroa.265.271.insert.mask, ptr %97, align 8, !pc !8
  %98 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 19, !pc !8
  store i64 %.sroa.175.191.insert.mask, ptr %98, align 8, !pc !8
  %99 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i32, i64, i64, i64, i64, i64 }>, ptr %4, i64 0, i32 20, !pc !8
  store i64 %13, ptr %99, align 8, !pc !8
  %100 = call ptr @basic_block_func4294983536(ptr nonnull %3, i64 ptrtoint (ptr @sub_100003f70__AIv_B_0 to i64), ptr null, ptr nonnull %2, ptr nonnull %4, ptr nonnull %80, ptr nonnull %81, ptr nonnull %82, ptr nonnull %83, ptr nonnull %84, ptr nonnull %85, ptr nonnull %86, ptr nonnull %87, ptr nonnull %88, ptr nonnull %89, ptr nonnull %90, ptr nonnull %91, ptr nonnull %92, ptr nonnull %93, ptr nonnull %94, ptr nonnull %95, ptr nonnull %96, ptr nonnull %97, ptr nonnull %98, ptr nonnull %99) #12, !pc !8
  unreachable, !pc !8
}

; Function Attrs: noinline
define ptr @basic_block_func4294983576(ptr %stack, i64 %program_counter, ptr %memory, ptr %next_pc_out, ptr noalias %X24, ptr noalias %X22, ptr noalias %X20, ptr noalias %X25, ptr noalias %X28, ptr noalias %X23, ptr noalias %X21, ptr noalias %D13, ptr noalias %D9, ptr noalias %D12, ptr noalias %X26, ptr noalias %X29, ptr noalias %D14, ptr noalias %X30, ptr noalias %X19, ptr noalias %D8, ptr noalias %D11, ptr noalias %D15, ptr noalias %D10, ptr noalias %X27) local_unnamed_addr #9 !__anvill_basic_block_md !9 {
  call void (...) @__anvill_basic_block_function_return(i32 0)
  ret ptr %memory
}

; Function Attrs: noinline
define i32 @sub_100003f98__AvI_B_0() local_unnamed_addr #9 !pc !9 {
  %1 = alloca [0 x i8], align 4, !pc !9
  %2 = alloca i64, align 8, !pc !9
  %3 = alloca <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, align 8, !pc !9
  %4 = load i64, ptr @__anvill_reg_X19, align 8, !pc !9
  %5 = load i64, ptr @__anvill_reg_X20, align 8, !pc !9
  %6 = load i64, ptr @__anvill_reg_X21, align 8, !pc !9
  %7 = load i64, ptr @__anvill_reg_X22, align 8, !pc !9
  %8 = load i64, ptr @__anvill_reg_X23, align 8, !pc !9
  %9 = load i64, ptr @__anvill_reg_X24, align 8, !pc !9
  %10 = load i64, ptr @__anvill_reg_X25, align 8, !pc !9
  %11 = load i64, ptr @__anvill_reg_X26, align 8, !pc !9
  %12 = load i64, ptr @__anvill_reg_X27, align 8, !pc !9
  %13 = load i64, ptr @__anvill_reg_X28, align 8, !pc !9
  %14 = load i64, ptr @__anvill_reg_X29, align 8, !pc !9
  %15 = load i8, ptr @__anvill_reg_V8, align 1, !pc !9
  %16 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 1), align 1, !pc !9
  %17 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 2), align 1, !pc !9
  %18 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 3), align 1, !pc !9
  %19 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 4), align 1, !pc !9
  %20 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 5), align 1, !pc !9
  %21 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 6), align 1, !pc !9
  %22 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V8, i64 0, i64 7), align 1, !pc !9
  %.sroa.139.144.insert.ext = zext i8 %15 to i64, !pc !9
  %.sroa.139.145.insert.ext = zext i8 %16 to i64, !pc !9
  %.sroa.139.145.insert.shift = shl nuw nsw i64 %.sroa.139.145.insert.ext, 8, !pc !9
  %.sroa.139.145.insert.insert = or i64 %.sroa.139.145.insert.shift, %.sroa.139.144.insert.ext, !pc !9
  %.sroa.139.146.insert.ext = zext i8 %17 to i64, !pc !9
  %.sroa.139.146.insert.shift = shl nuw nsw i64 %.sroa.139.146.insert.ext, 16, !pc !9
  %.sroa.139.146.insert.insert = or i64 %.sroa.139.145.insert.insert, %.sroa.139.146.insert.shift, !pc !9
  %.sroa.139.147.insert.ext = zext i8 %18 to i64, !pc !9
  %.sroa.139.147.insert.shift = shl nuw nsw i64 %.sroa.139.147.insert.ext, 24, !pc !9
  %.sroa.139.147.insert.insert = or i64 %.sroa.139.146.insert.insert, %.sroa.139.147.insert.shift, !pc !9
  %.sroa.139.148.insert.ext = zext i8 %19 to i64, !pc !9
  %.sroa.139.148.insert.shift = shl nuw nsw i64 %.sroa.139.148.insert.ext, 32, !pc !9
  %.sroa.139.149.insert.ext = zext i8 %20 to i64, !pc !9
  %.sroa.139.149.insert.shift = shl nuw nsw i64 %.sroa.139.149.insert.ext, 40, !pc !9
  %.sroa.139.149.insert.mask = or i64 %.sroa.139.147.insert.insert, %.sroa.139.148.insert.shift, !pc !9
  %.sroa.139.150.insert.ext = zext i8 %21 to i64, !pc !9
  %.sroa.139.150.insert.shift = shl nuw nsw i64 %.sroa.139.150.insert.ext, 48, !pc !9
  %.sroa.139.151.insert.ext = zext i8 %22 to i64, !pc !9
  %.sroa.139.151.insert.shift = shl nuw i64 %.sroa.139.151.insert.ext, 56, !pc !9
  %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.149.insert.mask, %.sroa.139.149.insert.shift, !pc !9
  %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.139.150.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.150.insert.shift, !pc !9
  %.sroa.139.159.insert.mask = or i64 %.sroa.139.151.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.139.151.insert.shift, !pc !9
  %23 = load i8, ptr @__anvill_reg_V9, align 1, !pc !9
  %24 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 1), align 1, !pc !9
  %25 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 2), align 1, !pc !9
  %26 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 3), align 1, !pc !9
  %27 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 4), align 1, !pc !9
  %28 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 5), align 1, !pc !9
  %29 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 6), align 1, !pc !9
  %30 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V9, i64 0, i64 7), align 1, !pc !9
  %.sroa.157.160.insert.ext = zext i8 %23 to i64, !pc !9
  %.sroa.157.161.insert.ext = zext i8 %24 to i64, !pc !9
  %.sroa.157.161.insert.shift = shl nuw nsw i64 %.sroa.157.161.insert.ext, 8, !pc !9
  %.sroa.157.161.insert.insert = or i64 %.sroa.157.161.insert.shift, %.sroa.157.160.insert.ext, !pc !9
  %.sroa.157.162.insert.ext = zext i8 %25 to i64, !pc !9
  %.sroa.157.162.insert.shift = shl nuw nsw i64 %.sroa.157.162.insert.ext, 16, !pc !9
  %.sroa.157.162.insert.insert = or i64 %.sroa.157.161.insert.insert, %.sroa.157.162.insert.shift, !pc !9
  %.sroa.157.163.insert.ext = zext i8 %26 to i64, !pc !9
  %.sroa.157.163.insert.shift = shl nuw nsw i64 %.sroa.157.163.insert.ext, 24, !pc !9
  %.sroa.157.163.insert.insert = or i64 %.sroa.157.162.insert.insert, %.sroa.157.163.insert.shift, !pc !9
  %.sroa.157.164.insert.ext = zext i8 %27 to i64, !pc !9
  %.sroa.157.164.insert.shift = shl nuw nsw i64 %.sroa.157.164.insert.ext, 32, !pc !9
  %.sroa.157.165.insert.ext = zext i8 %28 to i64, !pc !9
  %.sroa.157.165.insert.shift = shl nuw nsw i64 %.sroa.157.165.insert.ext, 40, !pc !9
  %.sroa.157.165.insert.mask = or i64 %.sroa.157.163.insert.insert, %.sroa.157.164.insert.shift, !pc !9
  %.sroa.157.166.insert.ext = zext i8 %29 to i64, !pc !9
  %.sroa.157.166.insert.shift = shl nuw nsw i64 %.sroa.157.166.insert.ext, 48, !pc !9
  %.sroa.157.167.insert.ext = zext i8 %30 to i64, !pc !9
  %.sroa.157.167.insert.shift = shl nuw i64 %.sroa.157.167.insert.ext, 56, !pc !9
  %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.165.insert.mask, %.sroa.157.165.insert.shift, !pc !9
  %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.157.166.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.166.insert.shift, !pc !9
  %.sroa.157.175.insert.mask = or i64 %.sroa.157.167.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.157.167.insert.shift, !pc !9
  %31 = load i8, ptr @__anvill_reg_V10, align 1, !pc !9
  %32 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 1), align 1, !pc !9
  %33 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 2), align 1, !pc !9
  %34 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 3), align 1, !pc !9
  %35 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 4), align 1, !pc !9
  %36 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 5), align 1, !pc !9
  %37 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 6), align 1, !pc !9
  %38 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V10, i64 0, i64 7), align 1, !pc !9
  %.sroa.175.176.insert.ext = zext i8 %31 to i64, !pc !9
  %.sroa.175.177.insert.ext = zext i8 %32 to i64, !pc !9
  %.sroa.175.177.insert.shift = shl nuw nsw i64 %.sroa.175.177.insert.ext, 8, !pc !9
  %.sroa.175.177.insert.insert = or i64 %.sroa.175.177.insert.shift, %.sroa.175.176.insert.ext, !pc !9
  %.sroa.175.178.insert.ext = zext i8 %33 to i64, !pc !9
  %.sroa.175.178.insert.shift = shl nuw nsw i64 %.sroa.175.178.insert.ext, 16, !pc !9
  %.sroa.175.178.insert.insert = or i64 %.sroa.175.177.insert.insert, %.sroa.175.178.insert.shift, !pc !9
  %.sroa.175.179.insert.ext = zext i8 %34 to i64, !pc !9
  %.sroa.175.179.insert.shift = shl nuw nsw i64 %.sroa.175.179.insert.ext, 24, !pc !9
  %.sroa.175.179.insert.insert = or i64 %.sroa.175.178.insert.insert, %.sroa.175.179.insert.shift, !pc !9
  %.sroa.175.180.insert.ext = zext i8 %35 to i64, !pc !9
  %.sroa.175.180.insert.shift = shl nuw nsw i64 %.sroa.175.180.insert.ext, 32, !pc !9
  %.sroa.175.181.insert.ext = zext i8 %36 to i64, !pc !9
  %.sroa.175.181.insert.shift = shl nuw nsw i64 %.sroa.175.181.insert.ext, 40, !pc !9
  %.sroa.175.181.insert.mask = or i64 %.sroa.175.179.insert.insert, %.sroa.175.180.insert.shift, !pc !9
  %.sroa.175.182.insert.ext = zext i8 %37 to i64, !pc !9
  %.sroa.175.182.insert.shift = shl nuw nsw i64 %.sroa.175.182.insert.ext, 48, !pc !9
  %.sroa.175.183.insert.ext = zext i8 %38 to i64, !pc !9
  %.sroa.175.183.insert.shift = shl nuw i64 %.sroa.175.183.insert.ext, 56, !pc !9
  %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.181.insert.mask, %.sroa.175.181.insert.shift, !pc !9
  %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.175.182.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.182.insert.shift, !pc !9
  %.sroa.175.191.insert.mask = or i64 %.sroa.175.183.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.175.183.insert.shift, !pc !9
  %39 = load i8, ptr @__anvill_reg_V11, align 1, !pc !9
  %40 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 1), align 1, !pc !9
  %41 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 2), align 1, !pc !9
  %42 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 3), align 1, !pc !9
  %43 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 4), align 1, !pc !9
  %44 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 5), align 1, !pc !9
  %45 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 6), align 1, !pc !9
  %46 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V11, i64 0, i64 7), align 1, !pc !9
  %.sroa.193.192.insert.ext = zext i8 %39 to i64, !pc !9
  %.sroa.193.193.insert.ext = zext i8 %40 to i64, !pc !9
  %.sroa.193.193.insert.shift = shl nuw nsw i64 %.sroa.193.193.insert.ext, 8, !pc !9
  %.sroa.193.193.insert.insert = or i64 %.sroa.193.193.insert.shift, %.sroa.193.192.insert.ext, !pc !9
  %.sroa.193.194.insert.ext = zext i8 %41 to i64, !pc !9
  %.sroa.193.194.insert.shift = shl nuw nsw i64 %.sroa.193.194.insert.ext, 16, !pc !9
  %.sroa.193.194.insert.insert = or i64 %.sroa.193.193.insert.insert, %.sroa.193.194.insert.shift, !pc !9
  %.sroa.193.195.insert.ext = zext i8 %42 to i64, !pc !9
  %.sroa.193.195.insert.shift = shl nuw nsw i64 %.sroa.193.195.insert.ext, 24, !pc !9
  %.sroa.193.195.insert.insert = or i64 %.sroa.193.194.insert.insert, %.sroa.193.195.insert.shift, !pc !9
  %.sroa.193.196.insert.ext = zext i8 %43 to i64, !pc !9
  %.sroa.193.196.insert.shift = shl nuw nsw i64 %.sroa.193.196.insert.ext, 32, !pc !9
  %.sroa.193.197.insert.ext = zext i8 %44 to i64, !pc !9
  %.sroa.193.197.insert.shift = shl nuw nsw i64 %.sroa.193.197.insert.ext, 40, !pc !9
  %.sroa.193.197.insert.mask = or i64 %.sroa.193.195.insert.insert, %.sroa.193.196.insert.shift, !pc !9
  %.sroa.193.198.insert.ext = zext i8 %45 to i64, !pc !9
  %.sroa.193.198.insert.shift = shl nuw nsw i64 %.sroa.193.198.insert.ext, 48, !pc !9
  %.sroa.193.199.insert.ext = zext i8 %46 to i64, !pc !9
  %.sroa.193.199.insert.shift = shl nuw i64 %.sroa.193.199.insert.ext, 56, !pc !9
  %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.197.insert.mask, %.sroa.193.197.insert.shift, !pc !9
  %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.193.198.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.198.insert.shift, !pc !9
  %.sroa.193.207.insert.mask = or i64 %.sroa.193.199.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.193.199.insert.shift, !pc !9
  %47 = load i8, ptr @__anvill_reg_V12, align 1, !pc !9
  %48 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 1), align 1, !pc !9
  %49 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 2), align 1, !pc !9
  %50 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 3), align 1, !pc !9
  %51 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 4), align 1, !pc !9
  %52 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 5), align 1, !pc !9
  %53 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 6), align 1, !pc !9
  %54 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V12, i64 0, i64 7), align 1, !pc !9
  %.sroa.211.208.insert.ext = zext i8 %47 to i64, !pc !9
  %.sroa.211.209.insert.ext = zext i8 %48 to i64, !pc !9
  %.sroa.211.209.insert.shift = shl nuw nsw i64 %.sroa.211.209.insert.ext, 8, !pc !9
  %.sroa.211.209.insert.insert = or i64 %.sroa.211.209.insert.shift, %.sroa.211.208.insert.ext, !pc !9
  %.sroa.211.210.insert.ext = zext i8 %49 to i64, !pc !9
  %.sroa.211.210.insert.shift = shl nuw nsw i64 %.sroa.211.210.insert.ext, 16, !pc !9
  %.sroa.211.210.insert.insert = or i64 %.sroa.211.209.insert.insert, %.sroa.211.210.insert.shift, !pc !9
  %.sroa.211.211.insert.ext = zext i8 %50 to i64, !pc !9
  %.sroa.211.211.insert.shift = shl nuw nsw i64 %.sroa.211.211.insert.ext, 24, !pc !9
  %.sroa.211.211.insert.insert = or i64 %.sroa.211.210.insert.insert, %.sroa.211.211.insert.shift, !pc !9
  %.sroa.211.212.insert.ext = zext i8 %51 to i64, !pc !9
  %.sroa.211.212.insert.shift = shl nuw nsw i64 %.sroa.211.212.insert.ext, 32, !pc !9
  %.sroa.211.213.insert.ext = zext i8 %52 to i64, !pc !9
  %.sroa.211.213.insert.shift = shl nuw nsw i64 %.sroa.211.213.insert.ext, 40, !pc !9
  %.sroa.211.213.insert.mask = or i64 %.sroa.211.211.insert.insert, %.sroa.211.212.insert.shift, !pc !9
  %.sroa.211.214.insert.ext = zext i8 %53 to i64, !pc !9
  %.sroa.211.214.insert.shift = shl nuw nsw i64 %.sroa.211.214.insert.ext, 48, !pc !9
  %.sroa.211.215.insert.ext = zext i8 %54 to i64, !pc !9
  %.sroa.211.215.insert.shift = shl nuw i64 %.sroa.211.215.insert.ext, 56, !pc !9
  %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.213.insert.mask, %.sroa.211.213.insert.shift, !pc !9
  %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.211.214.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.214.insert.shift, !pc !9
  %.sroa.211.223.insert.mask = or i64 %.sroa.211.215.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.211.215.insert.shift, !pc !9
  %55 = load i8, ptr @__anvill_reg_V13, align 1, !pc !9
  %56 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 1), align 1, !pc !9
  %57 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 2), align 1, !pc !9
  %58 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 3), align 1, !pc !9
  %59 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 4), align 1, !pc !9
  %60 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 5), align 1, !pc !9
  %61 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 6), align 1, !pc !9
  %62 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V13, i64 0, i64 7), align 1, !pc !9
  %.sroa.229.224.insert.ext = zext i8 %55 to i64, !pc !9
  %.sroa.229.225.insert.ext = zext i8 %56 to i64, !pc !9
  %.sroa.229.225.insert.shift = shl nuw nsw i64 %.sroa.229.225.insert.ext, 8, !pc !9
  %.sroa.229.225.insert.insert = or i64 %.sroa.229.225.insert.shift, %.sroa.229.224.insert.ext, !pc !9
  %.sroa.229.226.insert.ext = zext i8 %57 to i64, !pc !9
  %.sroa.229.226.insert.shift = shl nuw nsw i64 %.sroa.229.226.insert.ext, 16, !pc !9
  %.sroa.229.226.insert.insert = or i64 %.sroa.229.225.insert.insert, %.sroa.229.226.insert.shift, !pc !9
  %.sroa.229.227.insert.ext = zext i8 %58 to i64, !pc !9
  %.sroa.229.227.insert.shift = shl nuw nsw i64 %.sroa.229.227.insert.ext, 24, !pc !9
  %.sroa.229.227.insert.insert = or i64 %.sroa.229.226.insert.insert, %.sroa.229.227.insert.shift, !pc !9
  %.sroa.229.228.insert.ext = zext i8 %59 to i64, !pc !9
  %.sroa.229.228.insert.shift = shl nuw nsw i64 %.sroa.229.228.insert.ext, 32, !pc !9
  %.sroa.229.229.insert.ext = zext i8 %60 to i64, !pc !9
  %.sroa.229.229.insert.shift = shl nuw nsw i64 %.sroa.229.229.insert.ext, 40, !pc !9
  %.sroa.229.229.insert.mask = or i64 %.sroa.229.227.insert.insert, %.sroa.229.228.insert.shift, !pc !9
  %.sroa.229.230.insert.ext = zext i8 %61 to i64, !pc !9
  %.sroa.229.230.insert.shift = shl nuw nsw i64 %.sroa.229.230.insert.ext, 48, !pc !9
  %.sroa.229.231.insert.ext = zext i8 %62 to i64, !pc !9
  %.sroa.229.231.insert.shift = shl nuw i64 %.sroa.229.231.insert.ext, 56, !pc !9
  %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.229.insert.mask, %.sroa.229.229.insert.shift, !pc !9
  %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.229.230.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.230.insert.shift, !pc !9
  %.sroa.229.239.insert.mask = or i64 %.sroa.229.231.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.229.231.insert.shift, !pc !9
  %63 = load i8, ptr @__anvill_reg_V14, align 1, !pc !9
  %64 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 1), align 1, !pc !9
  %65 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 2), align 1, !pc !9
  %66 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 3), align 1, !pc !9
  %67 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 4), align 1, !pc !9
  %68 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 5), align 1, !pc !9
  %69 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 6), align 1, !pc !9
  %70 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V14, i64 0, i64 7), align 1, !pc !9
  %.sroa.247.240.insert.ext = zext i8 %63 to i64, !pc !9
  %.sroa.247.241.insert.ext = zext i8 %64 to i64, !pc !9
  %.sroa.247.241.insert.shift = shl nuw nsw i64 %.sroa.247.241.insert.ext, 8, !pc !9
  %.sroa.247.241.insert.insert = or i64 %.sroa.247.241.insert.shift, %.sroa.247.240.insert.ext, !pc !9
  %.sroa.247.242.insert.ext = zext i8 %65 to i64, !pc !9
  %.sroa.247.242.insert.shift = shl nuw nsw i64 %.sroa.247.242.insert.ext, 16, !pc !9
  %.sroa.247.242.insert.insert = or i64 %.sroa.247.241.insert.insert, %.sroa.247.242.insert.shift, !pc !9
  %.sroa.247.243.insert.ext = zext i8 %66 to i64, !pc !9
  %.sroa.247.243.insert.shift = shl nuw nsw i64 %.sroa.247.243.insert.ext, 24, !pc !9
  %.sroa.247.243.insert.insert = or i64 %.sroa.247.242.insert.insert, %.sroa.247.243.insert.shift, !pc !9
  %.sroa.247.244.insert.ext = zext i8 %67 to i64, !pc !9
  %.sroa.247.244.insert.shift = shl nuw nsw i64 %.sroa.247.244.insert.ext, 32, !pc !9
  %.sroa.247.245.insert.ext = zext i8 %68 to i64, !pc !9
  %.sroa.247.245.insert.shift = shl nuw nsw i64 %.sroa.247.245.insert.ext, 40, !pc !9
  %.sroa.247.245.insert.mask = or i64 %.sroa.247.243.insert.insert, %.sroa.247.244.insert.shift, !pc !9
  %.sroa.247.246.insert.ext = zext i8 %69 to i64, !pc !9
  %.sroa.247.246.insert.shift = shl nuw nsw i64 %.sroa.247.246.insert.ext, 48, !pc !9
  %.sroa.247.247.insert.ext = zext i8 %70 to i64, !pc !9
  %.sroa.247.247.insert.shift = shl nuw i64 %.sroa.247.247.insert.ext, 56, !pc !9
  %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.245.insert.mask, %.sroa.247.245.insert.shift, !pc !9
  %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.247.246.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.246.insert.shift, !pc !9
  %.sroa.247.255.insert.mask = or i64 %.sroa.247.247.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.247.247.insert.shift, !pc !9
  %71 = load i8, ptr @__anvill_reg_V15, align 1, !pc !9
  %72 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 1), align 1, !pc !9
  %73 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 2), align 1, !pc !9
  %74 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 3), align 1, !pc !9
  %75 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 4), align 1, !pc !9
  %76 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 5), align 1, !pc !9
  %77 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 6), align 1, !pc !9
  %78 = load i8, ptr getelementptr inbounds ([16 x i8], ptr @__anvill_reg_V15, i64 0, i64 7), align 1, !pc !9
  %.sroa.265.256.insert.ext = zext i8 %71 to i64, !pc !9
  %.sroa.265.257.insert.ext = zext i8 %72 to i64, !pc !9
  %.sroa.265.257.insert.shift = shl nuw nsw i64 %.sroa.265.257.insert.ext, 8, !pc !9
  %.sroa.265.257.insert.insert = or i64 %.sroa.265.257.insert.shift, %.sroa.265.256.insert.ext, !pc !9
  %.sroa.265.258.insert.ext = zext i8 %73 to i64, !pc !9
  %.sroa.265.258.insert.shift = shl nuw nsw i64 %.sroa.265.258.insert.ext, 16, !pc !9
  %.sroa.265.258.insert.insert = or i64 %.sroa.265.257.insert.insert, %.sroa.265.258.insert.shift, !pc !9
  %.sroa.265.259.insert.ext = zext i8 %74 to i64, !pc !9
  %.sroa.265.259.insert.shift = shl nuw nsw i64 %.sroa.265.259.insert.ext, 24, !pc !9
  %.sroa.265.259.insert.insert = or i64 %.sroa.265.258.insert.insert, %.sroa.265.259.insert.shift, !pc !9
  %.sroa.265.260.insert.ext = zext i8 %75 to i64, !pc !9
  %.sroa.265.260.insert.shift = shl nuw nsw i64 %.sroa.265.260.insert.ext, 32, !pc !9
  %.sroa.265.261.insert.ext = zext i8 %76 to i64, !pc !9
  %.sroa.265.261.insert.shift = shl nuw nsw i64 %.sroa.265.261.insert.ext, 40, !pc !9
  %.sroa.265.261.insert.mask = or i64 %.sroa.265.259.insert.insert, %.sroa.265.260.insert.shift, !pc !9
  %.sroa.265.262.insert.ext = zext i8 %77 to i64, !pc !9
  %.sroa.265.262.insert.shift = shl nuw nsw i64 %.sroa.265.262.insert.ext, 48, !pc !9
  %.sroa.265.263.insert.ext = zext i8 %78 to i64, !pc !9
  %.sroa.265.263.insert.shift = shl nuw i64 %.sroa.265.263.insert.ext, 56, !pc !9
  %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.261.insert.mask, %.sroa.265.261.insert.shift, !pc !9
  %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked = or i64 %.sroa.265.262.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.262.insert.shift, !pc !9
  %.sroa.265.271.insert.mask = or i64 %.sroa.265.263.insert.mask.masked.masked.masked.masked.masked.masked.masked.masked, %.sroa.265.263.insert.shift, !pc !9
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %2), !pc !9
  call void @llvm.lifetime.start.p0(i64 0, ptr nonnull %1), !pc !9
  call void @llvm.lifetime.start.p0(i64 160, ptr nonnull %3), !pc !9
  store i64 ptrtoint (ptr @sub_100003f98__AvI_B_0 to i64), ptr %2, align 8, !pc !9
  store i64 %9, ptr %3, align 8, !pc !9
  %79 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 1, !pc !9
  store i64 %7, ptr %79, align 8, !pc !9
  %80 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 2, !pc !9
  store i64 %5, ptr %80, align 8, !pc !9
  %81 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 3, !pc !9
  store i64 %10, ptr %81, align 8, !pc !9
  %82 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 4, !pc !9
  store i64 %13, ptr %82, align 8, !pc !9
  %83 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 5, !pc !9
  store i64 %8, ptr %83, align 8, !pc !9
  %84 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 6, !pc !9
  store i64 %6, ptr %84, align 8, !pc !9
  %85 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 7, !pc !9
  store i64 %.sroa.229.239.insert.mask, ptr %85, align 8, !pc !9
  %86 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 8, !pc !9
  store i64 %.sroa.157.175.insert.mask, ptr %86, align 8, !pc !9
  %87 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 9, !pc !9
  store i64 %.sroa.211.223.insert.mask, ptr %87, align 8, !pc !9
  %88 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 10, !pc !9
  store i64 %11, ptr %88, align 8, !pc !9
  %89 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 11, !pc !9
  store i64 %14, ptr %89, align 8, !pc !9
  %90 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 12, !pc !9
  store i64 %.sroa.247.255.insert.mask, ptr %90, align 8, !pc !9
  %91 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 13, !pc !9
  store i64 ptrtoint (ptr @__anvill_ra to i64), ptr %91, align 8, !pc !9
  %92 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 14, !pc !9
  store i64 %4, ptr %92, align 8, !pc !9
  %93 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 15, !pc !9
  store i64 %.sroa.139.159.insert.mask, ptr %93, align 8, !pc !9
  %94 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 16, !pc !9
  store i64 %.sroa.193.207.insert.mask, ptr %94, align 8, !pc !9
  %95 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 17, !pc !9
  store i64 %.sroa.265.271.insert.mask, ptr %95, align 8, !pc !9
  %96 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 18, !pc !9
  store i64 %.sroa.175.191.insert.mask, ptr %96, align 8, !pc !9
  %97 = getelementptr inbounds <{ i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }>, ptr %3, i64 0, i32 19, !pc !9
  store i64 %12, ptr %97, align 8, !pc !9
  %98 = call ptr @basic_block_func4294983576(ptr nonnull %1, i64 ptrtoint (ptr @sub_100003f98__AvI_B_0 to i64), ptr null, ptr nonnull %2, ptr nonnull %3, ptr nonnull %79, ptr nonnull %80, ptr nonnull %81, ptr nonnull %82, ptr nonnull %83, ptr nonnull %84, ptr nonnull %85, ptr nonnull %86, ptr nonnull %87, ptr nonnull %88, ptr nonnull %89, ptr nonnull %90, ptr nonnull %91, ptr nonnull %92, ptr nonnull %93, ptr nonnull %94, ptr nonnull %95, ptr nonnull %96, ptr nonnull %97) #12, !pc !9
  unreachable, !pc !9
}

declare void @__anvill_basic_block_function_return(...) local_unnamed_addr

attributes #0 = { mustprogress noduplicate noinline nounwind optnone ssp "frame-pointer"="all" "min-legal-vector-width"="0" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #2 = { mustprogress noduplicate nofree noinline nosync nounwind optnone readnone willreturn "frame-pointer"="all" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #3 = { noduplicate noinline nounwind optnone readnone "frame-pointer"="all" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #4 = { noduplicate noinline nounwind optnone readnone willreturn "frame-pointer"="all" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #5 = { mustprogress nofree nosync nounwind readnone willreturn "frame-pointer"="all" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #6 = { noduplicate noinline nounwind optnone "frame-pointer"="all" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #7 = { alwaysinline mustprogress nounwind "frame-pointer"="non-leaf" "min-legal-vector-width"="0" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #8 = { nounwind readnone willreturn "frame-pointer"="all" "no-builtins" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "tune-cpu"="generic" }
attributes #9 = { noinline }
attributes #10 = { argmemonly nocallback nofree nosync nounwind willreturn }
attributes #11 = { nobuiltin nounwind "no-builtins" }
attributes #12 = { nounwind }

!0 = !{i64 4294983680}
!1 = !{!"StructType", !2, !3, !2}
!2 = !{!"ArrayType", !3, i32 4}
!3 = !{!"BaseType", i32 10}
!4 = !{i64 4294983420}
!5 = !{i64 4294983452}
!6 = !{i64 4294983480}
!7 = !{i64 4294983516}
!8 = !{i64 4294983536}
!9 = !{i64 4294983576}
