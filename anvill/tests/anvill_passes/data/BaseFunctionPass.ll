; ModuleID = 'BaseFunctionPass'
source_filename = "BaseFunctionPass"

@__anvill_sp = external global i8

define i32 @SelectInstructions() {
entry:
  %0 = alloca i32, align 4
  store i32 0, i32* %0, align 4
  %1 = load i32, i32* %0, align 4
  %2 = icmp eq i32 %1, 0
  br i1 %2, label %first, label %second

first:                                            ; preds = %entry
  %3 = add i32 %1, 1
  br label %exit

second:                                           ; preds = %entry
  %4 = add i32 %1, 2
  br label %exit

exit:                                             ; preds = %second, %first
  %5 = phi i32 [ %3, %first ], [ %4, %second ]
  ret i32 %5
}

define i64 @InstructionReferencesStackPointer() {
entry:
  %0 = icmp eq i1 0, 0
  %1 = select i1 %0, i64 11, i64 22
  store i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 12), i32* inttoptr (i32 add (i32 sub (i32 ptrtoint (i8* @__anvill_sp to i32), i32 16), i32 -4) to i32*), align 4
  ret i64 %1
}
