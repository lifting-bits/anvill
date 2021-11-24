# C++ coding style of Anvill

- [Overview](#overview)
- [Naming scheme](#naming-scheme)
- [Comments and comment placement](#comments-and-comment-placement)
  * [To-dos and Notes](#to-dos-and-notes)
- [Line splitting](#line-splitting)
  * [Function parameters and arguments](#function-parameters-and-arguments)
    + [Approach 1](#approach-1)
    + [Approach 2](#approach-2)
  * [Conditionals](#conditionals)
- [Indentation, spacing, and braces.](#indentation--spacing--and-braces)
  * [C++ constructor initializer lists](#c---constructor-initializer-lists)
  * [Spacing around statements](#spacing-around-statements)
  * [Switch statements](#switch-statements)
  * [Goto labels](#goto-labels)
  * [Brace usage](#brace-usage)
    + [Switch statements](#switch-statements-1)
- [C++ Namespaces](#c---namespaces)
  * [Declaring namespaces](#declaring-namespaces)
  * [Using namespaces](#using-namespaces)
- [C preprocessor use](#c-preprocessor-use)

## Naming conventions

The following code sample shows various naming conventions used:

```c++
int gGlobalVar;
thread_local int tThreadLocalVar;
const int kConstGlobalVar;

int CapitalizedFunctionName(void);
static int AnotherCapitalizedFunctionName(void);

namespace lower {

}  // namespace lower

class CapitalizedClassName {
 public:
  int CapitalizedMethodName(int parameter_name) {
    int local_var_name = parameter_name;
    return local_var_name;
  }
  
  static int gClassGlobal;
  static const int kClassGlobalConstant;
};

enum EnumName {
  kEnumeratorName
};
```

Guidelines:
- Almost all symbols that would traditionally be visible across function
  or module boundaries follow CapitalCase.
- C++ namespaces are lower-case, using underscores for word separation.
- Data (global or thread-local variables) are prefixed with `g` for
  global, mutable variables, `k` for constant data that will not change,
  and `t` for thread-local, mutable variables. It is permissible to use
  `g` for thread-local variables.

## Comments and comment placement

As much as possible, use line comments, i.e. `//`. The following code sample shows example of
comment placement.

```c++
// This is a comment about the function below.
void Function(void) {
  
  // When a comment is the only thing on a line, then the prior line should be either empty, or if non-empty, contain
  // a single `}`. Notice how there is an empty line between this comment and the prototype of the function above.
  // Comments on a line should always be describe what is below them.
  
  int var;  // Comments after code on a line should be placed two spaces after what they are commenting.

  Foo(true  /* Embedded comment, usually to highlight the use of an optional parameter. */);
  
  // This comment documents the conditions being tested in the following `if` statement. This comment should describe
  // the "why" of the conditions being tested, not the "what". For example, if there is a special case that must be
  // checked, describe the special case and how it relates to things.
  if (gFoo) {
  
  // This commnt documents the conditions being tested in the following `else if` statement.
  } else if (gBar) {
  
  }
}

namespace foo {
namespace {

}  // namespace
}  // namespace foo
```

### To-dos and Notes

To-do and notes (something that you think should be highlighted, or is particularly interesting, or that
on your next viewing of the code is meant to jog your memory on how to interpret that code) should be
written as follows.

```c++
TODO(pag): Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
           labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco
           laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in
           voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
           non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

NOTE(artem): Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
             labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco
             laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in
             voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
             non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
```

Please indent split lines to align with the first word following the `: ` of your to-do or note. This helps
make such commends stand out from normal multi-line comments.

Notes and to-dos should always specify the (user)name of the person who wrote them. This is so that
when someone reads the note or to-do, they know who to ask about it (without having to search for it
via something like `git blame`).

## Line splitting

Anvill code is mostly broken around 80 columns. In practice, try to break lines before 90 columns.
If you use an IDE, it is recommended that you configure it to add a margin line at 80 columns so that
you know where the boundary is.

### Function parameters and arguments

Function parameter and argument splitting is somewhat ad hoc. Use what you personally think is most
readable or "pretty" when choosing between the approaches. The code sample below shows the two
approaches.

#### Approach 1

Below, all parameters are moved to subsequent lines, and the first parameter is indented by four spaces.

```c++
std::pair<bool, bool> Node<QueryView>::CanonicalizeColumnPair(
    COL *in_col, COL *out_col, const OptimizationContext &opt) noexcept;
    
// If we added even more parameters, the line splitting would keep going.
std::pair<bool, bool> Node<QueryView>::CanonicalizeColumnPair(
    COL *in_col, COL *out_col, const OptimizationContext &opt,
    COL *in_col, COL *out_col, const OptimizationContext &opt) noexcept;
```

#### Approach 2

Below, parameters are packed onto a line until they would exceed the margin, at which point they are
broken to the next line and indented to be aligned to column subsequent to the `(` that introduces the
parameter list.

```c++
std::pair<bool, bool> Node<QueryView>::CanonicalizeColumnPair(COL *a, COL *b
                                                              COL *c) noexcept;
```

### Conditionals

Below shows an example of line splitting for large conditional bodies. The conditional operator, `&&` or
`||` ends a line, and parenthesized sub-expressions introduce their own additonal single-space of
indentation.

```c++
  if (!is_used_in_merge &&
      !introduces_control_dep &&
      !sets_condition &&
      AllColumnsAreUsed()) {
```

Similarly:

```c++
  if (!is_used_in_merge &&
      (!introduces_control_dep ||
       !sets_condition) &&  // Additional single space to align after `(`.
      AllColumnsAreUsed()) {
```

Use your discretion to decide if the condition needs to be split across multiple lines.  For example, the
previous example would likely better be expressed as:

```c++
  if (!is_used_in_merge &&
      (!introduces_control_dep || !sets_condition) &&
      AllColumnsAreUsed()) {
```

## Indentation, spacing, and braces.

Anvill uses 2-space indendation. Tabs should not be used. If your editor / IDE
supports automatic replacement of tabs with spaces then configure that feature accordingly.

### C++ constructor initializer lists

C++ constructor initializer lists use four spaces of indentation before the `:`, and then two spaces for
all subsequent fields (to align all of the field names).

```
Foo::Foo(void)
    : field1(...),
      field2(...) {}
```

### Spacing around statements

Use the following code example as a guide for whitespace placement.

```c++
if (...) {

}

do {

} while (...);

for (;;) {

}

for (int i = 0; i < 10; ++i) {

}
```

### Switch statements

Switch cases are indented two spaces, and then case bodies are further indented by two spaces.

```c++
switch (...) {
  case 0:
    break;
  case 1:
  default:
    break;
}
```

### Goto labels

You may use `goto` statements, although please use them sparingly.
When using a `goto` statement, indent the label in line with the nearest
enclosing `}`. For example:

```void Foo(void) {
  goto bar;

bar:
  ...
}

void Bar(void) {
  if (...) {
    goto foo;
    
  foo:
    ...
  }
}
```

### Brace usage

All block statements must use braces. The above code sample is a good example of brace usage.


#### Switch statements

Switch cases are an example where the cases themselves do not need to use braces, unless they
introduce variables. If possible, use scoped initializers of `if` statements to introduce braces into a
case statement. Below are some examples of brace uses with switch cases.

```
switch (...) {
  case 0:
    if (auto var = ...; var) {
      ...
    }
    break;
  case 1: {
    auto var = ...;
    ...
    break;
  }
}
```

## C++ Namespaces

### Declaring namespaces

All code should be defined as either belonging to a namespace, or explicitly be embedded within an
`extern "C"` linkage scope.

Almost all code should be placed within the `hyde` namespace, and code that is private to a translation
unit should be further embedded within an anonymous namespace. The code sample below provides an
example of proper usage.

```c++
namespace hyde {
namespace {

}  // namespace
}  // namespace hyde
```

Embedded namespaces should not be indented. The closing brace of a namespace should be
commented with the namespace being closed.

When using linkage specifiers, either specify them inline, or like namespace.

```c++
extern "C" int InlineLinkageSpec(void);

extern "C" {
int NamespaceLikeLinkageSpec(void);
}  // extern C
```

### Using namespaces

Never use the `using namespace` feature of C++. Instead, prefer to always spell out foreign namespaces.
For example, always use `std::vector` instead of `using namespace std;` along with `vector`.

## C preprocessor use

Don't use C preprocessor macros for constant definitions. Instead, use `constexpr` global variables, or use
enumerations (with a defined base type).

Try to only `#inclde` what is used, preferring to forward-declare as much as possible to avoid excessive
`#include` directives.
