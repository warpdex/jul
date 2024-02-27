include("support.yul")

const UINT8_MAX   := 0xff
const UINT16_MAX  := 0xffff
const UINT24_MAX  := 0xffffff
const UINT32_MAX  := 0xffffffff
const UINT40_MAX  := 0xffffffffff
const UINT48_MAX  := 0xffffffffffff
const UINT56_MAX  := 0xffffffffffffff
const UINT64_MAX  := 0xffffffffffffffff
const UINT96_MAX  := 0xffffffffffffffffffffffff
const UINT128_MAX := 0xffffffffffffffffffffffffffffffff
const UINT160_MAX := 0xffffffffffffffffffffffffffffffffffffffff
const UINT192_MAX := 0xffffffffffffffffffffffffffffffffffffffffffffffff
const UINT224_MAX := 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff
const UINT256_MAX := 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

const INT8_MIN   := 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80
const INT16_MIN  := 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000
const INT24_MIN  := 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
const INT32_MIN  := 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000
const INT40_MIN  := 0xffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000000
const INT48_MIN  := 0xffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000
const INT56_MIN  := 0xffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000
const INT64_MIN  := 0xffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000
const INT96_MIN  := 0xffffffffffffffffffffffffffffffffffffffff800000000000000000000000
const INT128_MIN := 0xffffffffffffffffffffffffffffffff80000000000000000000000000000000
const INT160_MIN := 0xffffffffffffffffffffffff8000000000000000000000000000000000000000
const INT192_MIN := 0xffffffffffffffff800000000000000000000000000000000000000000000000
const INT224_MIN := 0xffffffff80000000000000000000000000000000000000000000000000000000
const INT256_MIN := 0x8000000000000000000000000000000000000000000000000000000000000000

const INT8_MAX   := 0x7f
const INT16_MAX  := 0x7fff
const INT24_MAX  := 0x7fffff
const INT32_MAX  := 0x7fffffff
const INT40_MAX  := 0x7fffffffff
const INT48_MAX  := 0x7fffffffffff
const INT56_MAX  := 0x7fffffffffffff
const INT64_MAX  := 0x7fffffffffffffff
const INT96_MAX  := 0x7fffffffffffffffffffffff
const INT128_MAX := 0x7fffffffffffffffffffffffffffffff
const INT160_MAX := 0x7fffffffffffffffffffffffffffffffffffffff
const INT192_MAX := 0x7fffffffffffffffffffffffffffffffffffffffffffffff
const INT224_MAX := 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
const INT256_MAX := 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

macro selector() := shr(224, calldataload(0))

macro neq(x, y) := iszero(eq(x, y))
macro lte(x, y) := iszero(gt(x, y))
macro gte(x, y) := iszero(lt(x, y))
macro slte(x, y) := iszero(sgt(x, y))
macro sgte(x, y) := iszero(slt(x, y))
// macro ucmp(x, y) := sub(gt(x, y), lt(x, y))
// macro scmp(x, y) := sub(sgt(x, y), slt(x, y))
// macro tsel(v, x, y) := xor(y, mul(xor(y, x), v))
macro neg(x) := sub(0, x)

macro testn(x, n) := and(shr(n, x), 1)
macro maskn(x, n) := and(x, sub(shl(n, 1), 1))
macro isset(w, f) := eq(and(w, f), f)

macro submod(x, y, m) := addmod(x, sub(m, y), m)
macro negmod(x, m) := mod(sub(m, x), m)

// Gas Cost: 12
macro __read_int(data, pos, start, mask) :=
  and(shr(sub(start, shl(3, pos)), data), mask)

// Gas Cost: 15
macro __mask(data, pos, start, mask) :=
  and(data, not(shl(sub(start, shl(3, pos)), mask)))

// Gas Cost: 12
macro __put_int(data, pos, val, start) :=
  or(data, shl(sub(start, shl(3, pos)), val))

// Gas Cost: 27
macro __write_int(data, pos, val, start, mask) :=
  __put_int(__mask(data, pos, start, mask), pos, val, start)

macro read8(data, pos) := byte(pos, data)
macro read16(data, pos) := __read_int(data, pos, 240, UINT16_MAX)
macro read24(data, pos) := __read_int(data, pos, 232, UINT24_MAX)
macro read32(data, pos) := __read_int(data, pos, 224, UINT32_MAX)
macro read40(data, pos) := __read_int(data, pos, 216, UINT40_MAX)
macro read48(data, pos) := __read_int(data, pos, 208, UINT48_MAX)
macro read56(data, pos) := __read_int(data, pos, 200, UINT56_MAX)
macro read64(data, pos) := __read_int(data, pos, 192, UINT64_MAX)
macro read96(data, pos) := __read_int(data, pos, 160, UINT96_MAX)
macro read128(data, pos) := __read_int(data, pos, 128, UINT128_MAX)
macro read160(data, pos) := __read_int(data, pos, 96, UINT160_MAX)
macro read192(data, pos) := __read_int(data, pos, 64, UINT192_MAX)
macro read224(data, pos) := __read_int(data, pos, 32, UINT224_MAX)

macro write8(data, pos, val) := __write_int(data, pos, val, 248, UINT8_MAX)
macro write16(data, pos, val) := __write_int(data, pos, val, 240, UINT16_MAX)
macro write24(data, pos, val) := __write_int(data, pos, val, 232, UINT24_MAX)
macro write32(data, pos, val) := __write_int(data, pos, val, 224, UINT32_MAX)
macro write40(data, pos, val) := __write_int(data, pos, val, 216, UINT40_MAX)
macro write48(data, pos, val) := __write_int(data, pos, val, 208, UINT48_MAX)
macro write56(data, pos, val) := __write_int(data, pos, val, 200, UINT56_MAX)
macro write64(data, pos, val) := __write_int(data, pos, val, 192, UINT64_MAX)
macro write96(data, pos, val) := __write_int(data, pos, val, 160, UINT96_MAX)
macro write128(data, pos, val) := __write_int(data, pos, val, 128, UINT128_MAX)
macro write160(data, pos, val) := __write_int(data, pos, val, 96, UINT160_MAX)
macro write192(data, pos, val) := __write_int(data, pos, val, 64, UINT192_MAX)
macro write224(data, pos, val) := __write_int(data, pos, val, 32, UINT224_MAX)

macro put8(data, pos, val) := __put_int(data, pos, val, 248)
macro put16(data, pos, val) := __put_int(data, pos, val, 240)
macro put24(data, pos, val) := __put_int(data, pos, val, 232)
macro put32(data, pos, val) := __put_int(data, pos, val, 224)
macro put40(data, pos, val) := __put_int(data, pos, val, 216)
macro put48(data, pos, val) := __put_int(data, pos, val, 208)
macro put56(data, pos, val) := __put_int(data, pos, val, 200)
macro put64(data, pos, val) := __put_int(data, pos, val, 192)
macro put96(data, pos, val) := __put_int(data, pos, val, 160)
macro put128(data, pos, val) := __put_int(data, pos, val, 128)
macro put160(data, pos, val) := __put_int(data, pos, val, 96)
macro put192(data, pos, val) := __put_int(data, pos, val, 64)
macro put224(data, pos, val) := __put_int(data, pos, val, 32)

macro calldataloadn(ptr, width) := shr(sub(256, width), calldataload(ptr))
macro calldataload8(ptr) := byte(0, calldataload(ptr))
macro calldataload16(ptr) := shr(240, calldataload(ptr))
macro calldataload24(ptr) := shr(232, calldataload(ptr))
macro calldataload32(ptr) := shr(224, calldataload(ptr))
macro calldataload40(ptr) := shr(216, calldataload(ptr))
macro calldataload48(ptr) := shr(208, calldataload(ptr))
macro calldataload56(ptr) := shr(200, calldataload(ptr))
macro calldataload64(ptr) := shr(192, calldataload(ptr))
macro calldataload96(ptr) := shr(160, calldataload(ptr))
macro calldataload128(ptr) := shr(128, calldataload(ptr))
macro calldataload160(ptr) := shr(96, calldataload(ptr))
macro calldataload192(ptr) := shr(64, calldataload(ptr))
macro calldataload224(ptr) := shr(32, calldataload(ptr))
macro calldataload256(ptr) := calldataload(ptr)

macro mloadn(ptr, width) := shr(sub(256, width), mload(ptr))
macro mload8(ptr) := byte(0, mload(ptr))
macro mload16(ptr) := shr(240, mload(ptr))
macro mload24(ptr) := shr(232, mload(ptr))
macro mload32(ptr) := shr(224, mload(ptr))
macro mload40(ptr) := shr(216, mload(ptr))
macro mload48(ptr) := shr(208, mload(ptr))
macro mload56(ptr) := shr(200, mload(ptr))
macro mload64(ptr) := shr(192, mload(ptr))
macro mload96(ptr) := shr(160, mload(ptr))
macro mload128(ptr) := shr(128, mload(ptr))
macro mload160(ptr) := shr(96, mload(ptr))
macro mload192(ptr) := shr(64, mload(ptr))
macro mload224(ptr) := shr(32, mload(ptr))
macro mload256(ptr) := mload(ptr)

macro mstoren(ptr, val, width) := mstore(ptr, shl(sub(256, width), val))
macro mstore16(ptr, val) := mstore(ptr, shl(240, val))
macro mstore24(ptr, val) := mstore(ptr, shl(232, val))
macro mstore32(ptr, val) := mstore(ptr, shl(224, val))
macro mstore40(ptr, val) := mstore(ptr, shl(216, val))
macro mstore48(ptr, val) := mstore(ptr, shl(208, val))
macro mstore56(ptr, val) := mstore(ptr, shl(200, val))
macro mstore64(ptr, val) := mstore(ptr, shl(192, val))
macro mstore96(ptr, val) := mstore(ptr, shl(160, val))
macro mstore128(ptr, val) := mstore(ptr, shl(128, val))
macro mstore160(ptr, val) := mstore(ptr, shl(96, val))
macro mstore192(ptr, val) := mstore(ptr, shl(64, val))
macro mstore224(ptr, val) := mstore(ptr, shl(32, val))
macro mstore256(ptr, val) := mstore(ptr, val)

macro mzero(zp, zn) := codecopy(zp, codesize(), zn)
// macro mzero(zp, zn) := calldatacopy(zp, calldatasize(), zn)

macro bswap16(x) := __bswap16(x)
macro bswap32(x) := __bswap32(x)
macro bswap64(x) := __bswap64(x)
macro safeadd(x, y) := __safeadd(x, y)
macro safeaddn(x, y, n) := __safeaddn(x, y, n)
macro safesub(x, y) := __safesub(x, y)
macro safemul(x, y) := __safemul(x, y)
macro safemuln(x, y) := __safemuln(x, y, n)
macro safeshl(n, x) := __safeshl(n, x)
macro safeshln(n, x, w) := __safeshln(n, x, w)
macro safediv(x, y) := __safediv(x, y)
macro safesdiv(x, y) := __safesdiv(x, y)
macro safemod(x, y) := __safemod(x, y)
macro safeload(x) := __safeload(x)
macro mload.string(ptr) := __mload_string(ptr)
macro calldataload.string(ptr) := __calldataload_string(ptr)

macro BLAKE2B_IV1 := __blake2b_iv1
macro BLAKE2B_IV2 := __blake2b_iv2

macro blake2f(zp, xp) := __blake2f(zp, xp)

function __bswap16(x) -> z {
  // Gas Cost: 15
  z := or(shl(8, and(x, 0x00ff)),
          shr(8, and(x, 0xff00)))
}

function __bswap32(x) -> z {
  // Gas Cost: 30
  z := x
  z := or(shl(16, and(z, 0x0000ffff)),
          shr(16, and(z, 0xffff0000)))
  z := or(shl( 8, and(z, 0x00ff00ff)),
          shr( 8, and(z, 0xff00ff00)))
}

function __bswap64(x) -> z {
  // Gas Cost: 45
  z := x
  z := or(shl(32, and(z, 0x00000000ffffffff)),
          shr(32, and(z, 0xffffffff00000000)))
  z := or(shl(16, and(z, 0x0000ffff0000ffff)),
          shr(16, and(z, 0xffff0000ffff0000)))
  z := or(shl( 8, and(z, 0x00ff00ff00ff00ff)),
          shr( 8, and(z, 0xff00ff00ff00ff00)))
}

function __safeadd(x, y) -> z {
  // Code Size: 5
  // Code Size (debug): 7
  // Gas Cost: 16
  z := add(x, y)

  if lt(z, y) {
    // __panic_debug(0x11)
    revert.debug("add() overflow")
  }
}

function __safeaddn(x, y, n) -> z {
  // Code Size: 7
  // Code Size (debug): 9
  // Gas Cost: 22
  z := add(x, y)

  if or(lt(z, y), shr(n, z)) {
    // __panic_debug(0x11)
    revert.debug("addn() overflow")
  }
}

function __safesub(x, y) -> z {
  // Code Size: 5
  // Code Size (debug): 7
  // Gas Cost: 16
  if lt(x, y) {
    // __panic_debug(0x11)
    revert.debug("sub() underflow")
  }

  z := sub(x, y)
}

function __safemul(x, y) -> z {
  // Code Size: 9
  // Code Size (debug): 11
  // Gas Cost: 39
  if iszero(y) {
    z := 0
    leave
  }

  z := mul(x, y)

  if xor(div(z, y), x) {
    // __panic_debug(0x11)
    revert.debug("mul() overflow")
  }
}

function __safemuln(x, y, n) -> z {
  // Code Size: 11
  // Code Size (debug): 13
  // Gas Cost: 45
  if iszero(y) {
    z := 0
    leave
  }

  z := mul(x, y)

  if or(xor(div(z, y), x), shr(n, z)) {
    // __panic_debug(0x11)
    revert.debug("muln() overflow")
  }
}

function __safeshl(n, x) -> z {
  // Code Size: 6
  // Code Size (debug): 8
  // Gas Cost: 22
  z := shl(n, x)

  if xor(shr(n, z), x) {
    // __panic_debug(0x11)
    revert.debug("shl() overflow")
  }
}

function __safeshln(n, x, w) -> z {
  // Code Size: 8
  // Code Size (debug): 10
  // Gas Cost: 28
  z := shl(n, x)

  if or(xor(shr(n, z), x), shr(w, z)) {
    // __panic_debug(0x11)
    revert.debug("shln() overflow")
  }
}

function __safediv(x, y) -> z {
  // Code Size: 5
  // Code Size (debug): 7
  // Gas Cost: 18
  if iszero(y) {
    // __panic_debug(0x12)
    revert.debug("divide by zero")
  }

  z := div(x, y)
}

function __safesdiv(x, y) -> z {
  // Code Size: 5
  // Code Size (debug): 7
  // Gas Cost: 18
  if iszero(y) {
    // __panic_debug(0x12)
    revert.debug("divide by zero")
  }

  z := sdiv(x, y)
}

function __safemod(x, y) -> z {
  // Code Size: 5
  // Code Size (debug): 7
  // Gas Cost: 18
  if iszero(y) {
    // __panic_debug(0x12)
    revert.debug("divide by zero")
  }

  z := mod(x, y)
}

macro safeadd8(x, y) := __safeaddn(x, y, 8)
macro safeadd16(x, y) := __safeaddn(x, y, 16)
macro safeadd24(x, y) := __safeaddn(x, y, 24)
macro safeadd32(x, y) := __safeaddn(x, y, 32)
macro safeadd40(x, y) := __safeaddn(x, y, 40)
macro safeadd48(x, y) := __safeaddn(x, y, 48)
macro safeadd56(x, y) := __safeaddn(x, y, 56)
macro safeadd64(x, y) := __safeaddn(x, y, 64)
macro safeadd96(x, y) := __safeaddn(x, y, 96)
macro safeadd128(x, y) := __safeaddn(x, y, 128)
macro safeadd160(x, y) := __safeaddn(x, y, 160)
macro safeadd192(x, y) := __safeaddn(x, y, 192)
macro safeadd224(x, y) := __safeaddn(x, y, 224)
macro safeadd256(x, y) := __safeadd(x, y)

function __safeload(x) -> z {
  // Code Size: 5
  // Code Size (debug): 7
  z := sload(x)

  if iszero(z) {
    revert.debug("sload(x)=0")
  }
}

function __mload_string(ptr) -> str, len {
  let end := add(ptr, 64)

  // Check bounds.
  @if defined(INLINE_ASM) {
    if lt(end, 64) {
      revert(0, 0)
    }
  } else {
    if or(lt(end, 64), gt(end, msize())) {
      revert(0, 0)
    }
  }

  len := mload(add(ptr, 0))
  str := mload(add(ptr, 32))

  // Should <= 31 bytes in length.
  if gt(len, 31) {
    revert(0, 0)
  }

  // let shift := sub(256, shl(3, len))
  // str := shl(shift, shr(shift, str))

  // Sanity check.
  if xor(iszero(str), iszero(len)) {
    revert(0, 0)
  }

  // Remaining bits should be zero.
  if shl(shl(3, len), str) {
    revert(0, 0)
  }
}

function __calldataload_string(ptr) -> str, len {
  let end := add(ptr, 64)

  // Check bounds.
  if or(lt(end, 64), gt(end, calldatasize())) {
    revert(0, 0)
  }

  len := calldataload(add(ptr, 0))
  str := calldataload(add(ptr, 32))

  // Should <= 32 bytes in length.
  if gt(len, 32) {
    revert(0, 0)
  }

  // let shift := sub(256, shl(3, len))
  // str := shl(shift, shr(shift, str))

  // Sanity check.
  if xor(iszero(str), iszero(len)) {
    revert(0, 0)
  }

  // Remaining bits should be zero.
  if shl(shl(3, len), str) {
    revert(0, 0)
  }
}

// macro log2(x) := __log2(x) // Handled elsewhere.
macro log10(x) := __log10(x)
macro log256(x) := __log256(x)

macro bitlen(x) := __bitlen(x)
macro declen(x) := __declen(x)
macro octlen(x) := __octlen(x)

macro digits2(x) := add(__log2(x), 1)
macro digits10(x) := add(__log10(x), 1)
macro digits256(x) := add(__log256(x), 1)

macro popcount(x) := __popcount(x)
macro ctz(x) := __ctz(x)
macro clz(x) := __clz(x)

// Gas Used (256 bit): 470
// Gas Used (2 bit): 224
function __log2(x) -> n {
  // Min Cost: 8 * 8 + 3 = 67
  // Max Cost: 8 * 16 - 3 = 125
  // Avg Cost: 96
  n := 0

  if shr(128, x) {
    x := shr(128, x)
    n := add(n, 128)
  }

  if shr(64, x) {
    x := shr(64, x)
    n := add(n, 64)
  }

  if shr(32, x) {
    x := shr(32, x)
    n := add(n, 32)
  }

  if shr(16, x) {
    x := shr(16, x)
    n := add(n, 16)
  }

  if shr(8, x) {
    x := shr(8, x)
    n := add(n, 8)
  }

  if shr(4, x) {
    x := shr(4, x)
    n := add(n, 4)
  }

  if shr(2, x) {
    x := shr(2, x)
    n := add(n, 2)
  }

  if shr(1, x) {
    n := add(n, 1)
  }
}

function __log10(x) -> n {
  // Min Cost: 7 * 13 + 5 = 96
  // Max Cost: 7 * 21 - 5 = 142
  // Avg Cost: 119
  n := 0

  if gte(x, 10000000000000000000000000000000000000000000000000000000000000000) {
    x := div(x, 10000000000000000000000000000000000000000000000000000000000000000)
    n := add(n, 64)
  }

  if gte(x, 100000000000000000000000000000000) {
    x := div(x, 100000000000000000000000000000000)
    n := add(n, 32)
  }

  if gte(x, 10000000000000000) {
    x := div(x, 10000000000000000)
    n := add(n, 16)
  }

  if gte(x, 100000000) {
    x := div(x, 100000000)
    n := add(n, 8)
  }

  if gte(x, 10000) {
    x := div(x, 10000)
    n := add(n, 4)
  }

  if gte(x, 100) {
    x := div(x, 100)
    n := add(n, 2)
  }

  if gte(x, 10) {
    n := add(n, 1)
  }
}

function __log256(x) -> n {
  // Min Cost: 4 * 8 + 3 = 35
  // Max Cost: 4 * 16 - 3 = 61
  // Avg Cost: 48
  n := 0

  if shr(128, x) {
    x := shr(128, x)
    n := add(n, 16)
  }

  if shr(64, x) {
    x := shr(64, x)
    n := add(n, 8)
  }

  if shr(32, x) {
    x := shr(32, x)
    n := add(n, 4)
  }

  if shr(16, x) {
    x := shr(16, x)
    n := add(n, 2)
  }

  if shr(8, x) {
    n := add(n, 1)
  }
}

function __bitlen(x) -> n {
  n := add(__log2(x), iszero(iszero(x)))
}

function __declen(x) -> n {
  n := add(__log10(x), iszero(iszero(x)))
}

function __octlen(x) -> n {
  n := add(__log256(x), iszero(iszero(x)))
}

// Gas Used: 235
function __popcount(x) -> n {
  // http://aggregate.org/MAGIC/#Population%20Count%20(Ones%20Count)
  // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
  // https://en.wikipedia.org/wiki/Popcount#Efficient_implementation
  let a := 0x5555555555555555555555555555555555555555555555555555555555555555
  let b := 0x3333333333333333333333333333333333333333333333333333333333333333
  let c := 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
  let d := 0x0101010101010101010101010101010101010101010101010101010101010101

  x := sub(x, and(shr(1, x), a))
  x := add(and(x, b), and(shr(2, x), b))
  x := mul(and(add(x, shr(4, x)), c), d)

  n := shr(248, x)
}

// Gas Used: 259
function __ctz(x) -> n {
  // http://aggregate.org/MAGIC/#Trailing%20Zero%20Count
  n := __popcount(sub(and(x, sub(0, x)), 1))
}

// Gas Used: 346?
function __clz(x) -> n {
  // http://aggregate.org/MAGIC/#Leading%20Zero%20Count
  x := or(x, shr(1, x))
  x := or(x, shr(2, x))
  x := or(x, shr(4, x))
  x := or(x, shr(8, x))
  x := or(x, shr(16, x))
  x := or(x, shr(32, x))
  x := or(x, shr(64, x))
  x := or(x, shr(128, x))
  n := sub(256, __popcount(x))
}

macro tsel(v, x, y) := __tsel(y, v, x)
macro ucmp(x, y) := __ucmp(x, y)
macro scmp(x, y) := __scmp(x, y)
macro umin(x, y) := __umin(y, x)
macro umax(x, y) := __umax(y, x)
macro smin(x, y) := __smin(y, x)
macro smax(x, y) := __smax(y, x)
macro abs(x) := __abs(x)
macro sign(x) := __sign(x)
macro div.floor(x, y) := div(x, y)
macro div.ceil(x, y) := __div_ceil(x, y)
macro div.round(x, y) := __div_round(x, y)

// Ternary selection: z = v ? x : y
function __tsel(y, v, x) -> z {
  // DUP3 XOR MUL XOR
  z := xor(y, mul(xor(y, x), v))
}

function __ucmp(x, y) -> z {
  // DUP1 DUP3 LT SWAP2 GT SUB
  z := sub(gt(x, y), lt(x, y))
}

function __scmp(x, y) -> z {
  // DUP1 DUP3 SLT SWAP2 SGT SUB
  z := sub(sgt(x, y), slt(x, y))
}

function __umin(y, x) -> z {
  // DUP2 DUP2 LT SWAP1 DUP3 XOR MUL XOR
  z := xor(y, mul(xor(y, x), lt(x, y)))
}

function __umax(y, x) -> z {
  // DUP2 DUP2 GT SWAP1 DUP3 XOR MUL XOR
  z := xor(y, mul(xor(y, x), gt(x, y)))
}

function __smin(y, x) -> z {
  // DUP2 DUP2 SLT SWAP1 DUP3 XOR MUL XOR
  z := xor(y, mul(xor(y, x), slt(x, y)))
}

function __smax(y, x) -> z {
  // DUP2 DUP2 SGT SWAP1 DUP3 XOR MUL XOR
  z := xor(y, mul(xor(y, x), sgt(x, y)))
}

function __abs(x) -> z {
  // PUSH1 0x01 DUP2 PUSH1 0xFF SAR OR MUL
  z := mul(x, or(sar(255, x), 1))
}

function __sign(x) -> z {
  // DUP1 ISZERO ISZERO SWAP1 PUSH1 0xFF SAR OR
  z := or(sar(255, x), iszero(iszero(x)))
}

function __div_ceil(x, y) -> z {
  // DUP1 DUP3 DIV SWAP2 MOD ISZERO ISZERO ADD
  z := add(div(x, y), iszero(iszero(mod(x, y))))
}

function __div_round(x, y) -> z {
  let q := div(x, y)
  let r := mod(x, y)

  // Exact.
  if iszero(r) {
    z := q
    leave
  }

  let half := shr(1, y)
  let odd := and(y, 1)

  // Round down.
  if or(lt(r, half), and(eq(r, half), odd)) {
    z := q
    leave
  }

  // Round up.
  z := add(q, 1)
}

macro setimmutable.string(ptr, name, str, len) :=
  setimmutable(ptr, name, or(str, len))

macro storeimmutable.string(name, str, len) :=
  storeimmutable(name, or(str, len))

macro loadimmutable.string(name) := __loadstring(loadimmutable(name))

function __loadstring(x) -> str, len {
  len := and(x, 0xff)
  str := xor(x, len)
}

macro revert.returndata() {
  returndatacopy(0, 0, returndatasize())
  revert(0, returndatasize())
}

macro create.hash(pos, sender, nonce) :=
  __create_hash(pos, sender, nonce)

function __create_hash(pos, sender, nonce) -> addr {
  // Requires 55 bytes of scratch.
  // address = keccak256(rlp([sender, nonce]))[12:]
  let size := 23

  if lt(nonce, 0x80) {
    mstore8(add(pos, 0), 0xd6) // 0xc0 | 22
    mstore8(add(pos, 1), 0x94) // 0x80 | 20
    mstore(add(pos, 2), shl(96, sender))
    mstore8(add(pos, 22), or(nonce, mul(0x80, iszero(nonce))))
  } else {
    let tmp := nonce
    let len := 1

    if shr(64, tmp) {
      revert(0, 0)
    }

    if shr(32, tmp) {
      tmp := shr(32, tmp)
      len := add(len, 4)
    }

    if shr(16, tmp) {
      tmp := shr(16, tmp)
      len := add(len, 2)
    }

    if shr(8, tmp) {
      len := add(len, 1)
    }

    mstore8(add(pos, 0), or(0xc0, add(22, len)))
    mstore8(add(pos, 1), 0x94) // 0x80 | 20
    mstore(add(pos, 2), shl(96, sender))
    mstore8(add(pos, 22), add(len, 0x80))
    mstore(add(pos, 23), shl(sub(256, shl(3, len)), nonce))

    size := add(23, len)
  }

  addr := keccak256(pos, size)
  addr := shr(96, shl(96, addr))
}

macro create2.hash(pos, sender, salt, code_hash) :=
  __create2_hash(pos, sender, salt, code_hash)

function __create2_hash(pos, sender, code_hash, salt) -> addr {
  // Requires 85 bytes of scratch.
  // address = H(0xff, sender, salt, H(code))
  mstore8(pos, 0xff)
  mstore(add(pos, 1), shl(96, sender))
  mstore(add(pos, 21), salt)
  mstore(add(pos, 53), code_hash)
  addr := keccak256(pos, 85)
  addr := shr(96, shl(96, addr))
}

macro mutex.init(expr) {
  function __mutex_key() -> key {
    key := expr
  }
}

macro mutex.check() := __mutex_check()
macro mutex.lock() := __mutex_lock()
macro mutex.unlock() := __mutex_unlock()

function __mutex_check() {
  @if gt(EVM_VERSION, 202304) { // Cancun
    // https://eips.ethereum.org/EIPS/eip-1153
    if tload(__mutex_key()) {
      revert(0, 0)
    }
  } else {
    if eq(sload(__mutex_key()), 2) {
      revert(0, 0)
    }
  }
}

function __mutex_lock() {
  let key := __mutex_key()

  @if gt(EVM_VERSION, 202304) { // Cancun
    // https://eips.ethereum.org/EIPS/eip-1153
    if tload(key) {
      revert(0, 0)
    }
    tstore(key, 1)
  } else {
    if eq(sload(key), 2) {
      revert(0, 0)
    }
    sstore(key, 2)
  }
}

function __mutex_unlock() {
  @if gt(EVM_VERSION, 202304) { // Cancun
    tstore(__mutex_key(), 0)
  } else {
    sstore(__mutex_key(), 1)
  }
}

macro verbatim.not(x) := verbatim_1i_1o(hex"19", x)
macro verbatim.shl(n, x) := verbatim_2i_1o(hex"1b", n, x)
macro verbatim.shr(n, x) := verbatim_2i_1o(hex"1c", n, x)
macro verbatim.mask(n) := sub(verbatim.shl(n, 1), 1)
macro verbatim.maskn(x, n) := and(x, verbatim.mask(n))
macro verbatim.pop(x) := verbatim_1i_0o(hex"50", x)
