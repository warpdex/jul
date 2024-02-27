# Yul Transpiler for Warp

Warning: currently incomplete.

Our Yul transpiler adds several features.

## Structs & Types

### Defining a struct

``` yul
// P2WPKH output
struct btc_output {
  uint64 value
  uint24 prefix := 0x160014
  bytes20 hash
}
```

Note that struct definitions are block scoped.

Structs also allow for unnamed members that act as padding:

``` yul
struct btc_output {
  bytes8 + // padding
  uint24 prefix := 0x160014
  bytes20 hash
}
```

### Initializing a struct

``` yul
let output := struct(btc_output, 100000000, @, 0xdeadbeef)
```

This will allocate and initialize a struct on the stack. Note that these
structs limited to 32 bytes. In essence, our yul structs are essentially bit
fields on a 256 bit integer. The structs are packed with no padding (unless
explicitly requested). All members are serialized as big-endian. The first
member starts at the most significant byte of the uint256 (i.e. the left-most
byte).

The at-sign (@) specifies that the default value (`0x160014`) should be used
for the `prefix` member.

### Accessing/assigning struct members

``` yul
let output:btc_output := mload(0)
let value := output->value
output->value := 100
```

Types in yul are specified as such: `[name]:[type]`. In order to access
members, a variable must be explicitly defined as having a struct type that was
declared earlier in the scope or in a parent scope.

If writing `output:btc_output` is too verbose due to the redundancy, one can do:

``` yul
let btc_output:@ := mload(0)
let value := btc_output->value
```

The at-sign (@) specifies that the type name is the same as the variable name.

### Casting member accesses

Sometimes casting between structs is useful. For example:

``` yul
struct btc_output1 {
  uint64 value
  uint24 prefix := 0x160014
  bytes20 hash
}

struct btc_output2 {
  uint64 value
  uint8 size := 0x16
  bytes22 script
}
```

Say we want to access the p2wpkh hash, but sometimes also the full script
without allocating two stack items.

``` yul
let output:btc_output1 := mload(0)
let hash := output->hash
let script := output:btc_output2->script // cast to btc_output2
```

## Methods and Calldata

Our transpiler makes defining methods and accessing calldata extremely easy.

### Defining Methods

The `method` keyword is similar to `function` except it allows for ABI types to
be passed in and accessed.

``` yul
method foobar(uint32 id, uint64 amount, bytes32[] hashes) {
  let id := calldata.id
  let amount := calldata.amount
  let hashes_ptr := calldata.hashes
}
```

This will transpile to:

``` yul
function __method_foobar() {
  let id := calldataload(4)
  let amount := calldataload(36)
  let hashes_ptr := add(calldataload(68), 4)
}
```

If we need the actual calldata offsets we can do:

``` yul
method foobar(uint32 id, uint64 amount, bytes32[] hashes) {
  let id_pos := &calldata.id
  let amount_pos := &calldata.amount
  let hashes_pos := &calldata.hashes
}
```

Yielding:

``` yul
function __method_foobar() {
  let id_pos := 4
  let amount_pos := 36
  let hashes_pos := 68
}
```

## Includes

The compiler adds an `include` construct.

```
include("helpers/util.yul")
```

Which will inline the entire file. Note that the child file DOES NOT get its
own scope. It exists within the current scope.

Paths are relative to the current file's dirname.

## Macros

The `macro` keyword is similar to a function, but has no return value(s).
However, a single expression can act as a return value.

For example:

``` yul
macro addmul(x, y, z) {
  add(x, mul(y, z))
}

let x := addmul(1, 2, 3)
```

Needless to say, the compiler will inline the macro:

``` yul
let x := add(1, mul(2, 3))
```

Expression folding will also kick in, producing:

``` yul
let x := 7
```

The above macro can also be written in a less verbose way:

``` yul
macro addmul(x, y, z) := add(x, mul(y, z))
```

Producing identical results.

More complicated constructs can also appear in macros:

``` yul
macro inline_contract(contract_name, method_name) {
  object contract_name {
    code {
      datacopy(0, dataoffset("Runtime"), datasize("Runtime"))
      return(0, datasize("Runtime"))
    }
    object "Runtime" {
      code {
        method method_name(uint32 x, uint32 y) {
          let x := add(calldata.x, calldata.y)
          sstore(0, x)
        }
        ...
      }
    }
  }
}

inline_contract("MyContract", AddTwoNumbers)
```

### Macro Constants/Definitions

This is the equivalent of `#define x y` in C.

``` yul
macro ONE_BTC := 100000000
```

Macros defined in this way will replace _any_ identifier, not just expressions
that look like function calls (in contrast to the above).

### Macro Scoping

Note that all macros are block scoped and can appear anywhere in the
translation unit, meaning one can do this:

``` yul
{
  macro X := 1
}
{
  macro X := 2
}
```

## Constants

The compiler adds a `const` keyword. This is a safer alternative to macro
constants, as it only replaces rvalues.

``` yul
const x := 1
const y := 2
let z := add(x, y)
```

Yields:

``` yul
let z := add(1, 2)
```

Once again, constants are block-scoped. This is fine:

``` yul
{
  const x := 1
  const y := 2
  let z := add(x, y)
}
{
  const x := 2
  const y := 3
  let z := add(x, y)
}
```

And in contrast to `let`, `const` declarations can appear _anywhere_, even in
the top-level scope.

## Compiler Builtins

The compiler can inline a number of helper functions/macros.

See etc/builtins.yul for a full list.
