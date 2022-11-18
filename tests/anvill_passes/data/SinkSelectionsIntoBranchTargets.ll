; ModuleID = 'SinkSelectionsIntoBranchTargets.ll'
source_filename = "SinkSelectionsIntoBranchTargets"

define void @SimpleCase() {
entry:
  %0 = alloca i64, align 8
  %1 = load i64, ptr %0, align 4
  %2 = icmp eq i64 %1, 1
  %3 = select i1 %2, i64 10, i64 20
  br i1 %2, label %4, label %6

4:                                                ; preds = %entry
  %5 = add i64 %3, 10
  br label %8

6:                                                ; preds = %entry
  %7 = add i64 %3, 20
  br label %8

8:                                                ; preds = %6, %4
  %9 = phi i64 [ %5, %4 ], [ %7, %6 ]
  ret void
}

define void @MultipleSelects() {
entry:
  %0 = alloca i64, align 8
  %1 = load i64, ptr %0, align 4
  %2 = icmp eq i64 %1, 1
  %3 = select i1 %2, i64 10, i64 20
  %4 = select i1 %2, i64 10, i64 20
  %5 = select i1 %2, i64 10, i64 20
  br i1 %2, label %6, label %10

6:                                                ; preds = %entry
  %7 = add i64 %3, 10
  %8 = add i64 %4, 10
  %9 = add i64 %5, 10
  br label %14

10:                                               ; preds = %entry
  %11 = add i64 %3, 20
  %12 = add i64 %4, 20
  %13 = add i64 %5, 20
  br label %14

14:                                               ; preds = %10, %6
  %15 = phi i64 [ %7, %6 ], [ %11, %10 ]
  %16 = phi i64 [ %8, %6 ], [ %12, %10 ]
  %17 = phi i64 [ %9, %6 ], [ %13, %10 ]
  ret void
}

define void @MultipleSelectUsages() {
entry:
  %0 = alloca i64, align 8
  %1 = load i64, ptr %0, align 4
  %2 = icmp eq i64 %1, 1
  %3 = select i1 %2, i64 10, i64 20
  br i1 %2, label %4, label %10

4:                                                ; preds = %entry
  %5 = add i64 %3, 10
  %6 = add i64 %3, 10
  %7 = add i64 %3, 10
  %8 = add i64 %5, %6
  %9 = add i64 %8, %7
  br label %16

10:                                               ; preds = %entry
  %11 = add i64 %3, 10
  %12 = add i64 %3, 10
  %13 = add i64 %3, 10
  %14 = add i64 %11, %12
  %15 = add i64 %14, %13
  br label %16

16:                                               ; preds = %10, %4
  %17 = phi i64 [ %9, %4 ], [ %15, %10 ]
  ret void
}
