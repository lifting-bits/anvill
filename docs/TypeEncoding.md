# Recursive type encoding in Anvill

Anvill enables recursively defined types to be encoded as short, ASCII strings.
A given type may admit multiple representations in this type, and so a given
type string should only be interpreted as uniquely identifying a particular
type if the producer of those type strings is consistent and predictable in how
it encodes type strings.

## Endianness

Type encodings in Anvill do not have a declared endianness. The interpretation
of multi-byte objects is inherited from the architecture specified in the
[JSON specification document](SpecificationFormat.md).

## Fundamental types

The basic elements of the type encoding follows.

| Representation | Size in bytes | C/C++-equivalent |
|--|--|--|
| `?` | 1 | `_Bool` or `bool` |
| `b` | 1 | `int8_t` or `signed char` |
| `B` | 1 | `uint8_t` or `unsigned char` |
| `h` | 2 | `int16_t` or `short` |
| `H` | 2 | `uint16_t` or `unsigned short` |
| `i` | 4 | `int32_t` or `int` |
| `I` | 4 | `uint32_t` or `unsigned` |
| `l` | 8 | `int64_t` or `long long` |
| `L` | 8 | `uint64_t` or `unsigned long long` |
| `o` | 16 | `int128_t` or `__int128` |
| `O` | 16 | `uint128_t` or `__uint128` |
| `e` | 2 | `float16_t` (IEEE754 half-precision floating point, or `binary16`) |
| `f` | 4 | `float` (IEEE754 single-precision floating point) |
| `d` | 8 | `double` (IEEE754 double-precision floating point) |
| `D` | 10 or 12 | `long double` (IEEE754 extended precision floating point) |
| `M` | 8 | `uint64_t` (x86 MMX vector type) |
| `Q` | 16 | `__float128` (IEEE754 quadruple-precision floating point) |
| `v` | 0 | `void` |

The `v` type is generally not usable (as it does not have a size). It can be
used in function types and pointer types.

## Pointer types

A pointer type is a `*` followed by a type string. For example, `*i` is interpreted
as an `int32_t *` in C. One special case is `*v`, a pointer to some kind of unknown
data. The C interpretation is `void *`. In LLVM bitcode, `*v` is interpreted as
`*B`.

The size of a pointer type is dependent on the architecture referenced in a
[specification document](SpecificationFormat.md). In practice, it is always
four or eight bytes.

## Vector types

Vector types are used for representing values to be used in SIMD operations.
Vector types have the form: `<` followed by an element type, followed by an `x`
(without leading or trailing spaces), followed by an positive integer for the
number of elements in the vector, followed by `>`. For example:

| Example | Intepretation |
|--|--|
| `<Bx8>` | Vector of eight `uint8_t` values |
| `<ix4>` | Vector of four `int32_t` values |

## Array types

Array types are similar to vector types; they use `[` and `]` as their delimiters.

| Example | Intepretation |
|--|--|
| `[Bx8]` | Array of eight `uint8_t` values |
| `[ix4]` | Array of four `int32_t` values |

## Structure types

Structure types are represented as a concatenation of type encodings, surrounded
by `{` and `}`. There is no padding between elements, and it the interpretation
is that all structures are packed (i.e. `__attribute__((packed))` in C). This
implies that all padding in structures is explicit in the type representation.

In practice, one source of portability challenges related to sizes/paddings is
structures containing extended precision floating point values (`D`, i.e. `long double`).
This is because this type may be represented by compilers using 10 bytes or 12
bytes, depending on whether or not the target architecture is specified as x86 or
amd64.

| Example | Interpretation |
|--|--|
| `{iiii}` | Structure containing four signed, 32-bit integers. |
| `{{i}[{i}x4]}` | Structure containing a structure containing a single integer, followed by an array of four structures containing a single integer. |

### Identified structure types

Structure types can be "named" or "identified" by an integer index. Identification
indexes are totally ordered, and start a `0` and must be sequential. If a structure
type is prefixed with `=` followed by an integer, then that structure type can be
referenced later using `%` followed by the same integer. For example, the following
represents a linked list of integers: `=0{*%0i}`. This type has the following
interpretation:

 * `=0`: The following structure type will be identifiable with `%0`.
 * `{`: We are creating a structure type.
 * `*%0`: The first type in the structure is a pointer to the identified structure.
 * `i`: The second type in the structure is an integer.
 * `}`: We are done creating the structure type.

# Function types

Function types encode the types of paramters and return values. Function types
are *not* pointer types. A function pointer type is a `*` followed by a function
type.

Function types always start with a `(` and end with a `)`. Between these delimiters
are a concatenation of types (with some additional symbols). The last type is
interpreted as the return type. The `&` symbol represents "variadic" arguments.
If a function type takes a variadic number of arguments, then `&` must appear
immediately before the return type.

There must always be at least one parameter type. If a function takes zero
arguments, then this required parameter type can be `v`. If a function takes
zero formal arguments, but accepts variadic arguments, then this required
parameter type can be `&`.

There must always be a return type. If a function does not return any values,
then its return type can be specified with `v`.

| Example | C equivalent | C++ equivalent | Interpretation |
|--|--|--|--|
| `(vv)` | `void(void)` | `void(void)` | A function taking no arguments and returning no values. |
| `(vi)` | `int(void)` | `int(void)` | A function taking no arguments and retuning no values. |
| `(&v)` | `void()` | `void(...)` | A function taking a variadic number of arguments, and returning no values. |
| `(i?f)` | `float(int, _Bool)` | `float(int, bool)` | A function taking an integer, a Boolean, and returning a float. |
| `(i&f)` | `float(int, ...)` | `float(int, ...)` | A function taking an integer and a variadic number of parameters, and returning a float. |

