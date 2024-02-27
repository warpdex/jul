// CALL_GAS = 40 (Homestead, 2016)
// CALL_GAS = 700 (Tangerine Whistle, EIP-150, 2016) (Byzantium, EIP-214, 2017)
// CALL_GAS = 100 (Berlin, EIP-2929, 2021)

function __check_memory_array(ptr, unit, pos) {
  @if defined(INLINE_ASM) {
    if shr(32, ptr) {
      revert(0, 0)
    }

    if shr(32, mload(add(ptr, pos))) {
      revert(0, 0)
    }
  } else {
    let size := msize()

    if shr(32, ptr) {
      revert(0, 0)
    }

    ptr := add(ptr, pos)

    if gt(add(ptr, 32), size) { // (ptr + 32 <= size)
      revert(0, 0)
    }

    let len := mload(ptr)

    if shr(32, len) {
      revert(0, 0)
    }

    len := mul(len, unit)

    if gt(add(add(ptr, 32), len), size) { // (ptr + 32 + len <= size)
      revert(0, 0)
    }
  }
}

function __check_calldata_array(off, unit) {
  let size := calldatasize()
  let ptr := calldataload(off)

  if shr(32, ptr) {
    revert(0, 0)
  }

  ptr := add(ptr, 4)

  if gt(add(ptr, 32), size) { // (ptr + 32 <= size)
    revert(0, 0)
  }

  let len := calldataload(ptr)

  if shr(32, len) {
    revert(0, 0)
  }

  len := mul(len, unit)

  if gt(add(add(ptr, 32), len), size) { // (ptr + 32 + len <= size)
    revert(0, 0)
  }
}

function __check_int(num, width) {
  @if iszero(defined(INLINE_ASM)) {
    verbatim_1i_0o(hex"50", num) // Ensure noinline.
  }

  // Code Size: 13 (possibly 11)
  let max := sub(shl(sub(width, 1), 1), 1)

  if and(gt(num, max), lt(num, not(max))) {
    revert(0, 0)
  }
}

// We need a code size of 12 or above to avoid the full inliner. See:
// https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/FullInliner.cpp#L227
// https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/Metrics.h#L52
// https://github.com/ethereum/solidity/blob/e44b8b9/libyul/optimiser/Metrics.cpp#L38
function __revert32(msg, len) {
  // Code Size: 11
  // https://docs.soliditylang.org/en/v0.8.20/control-structures.html#revert
  mstore(0, shl(224, 0x08c379a0)) // keccak256("Error(string)")
  mstore(4, 32)
  mstore(36, len)
  mstore(68, msg)
  mstore(101, 0) // New Size: 13
  revert(0, 100)
}

function __revert64(left, right, len) {
  // Code Size: 13
  // https://docs.soliditylang.org/en/v0.8.20/control-structures.html#revert
  mstore(0, shl(224, 0x08c379a0)) // keccak256("Error(string)")
  mstore(4, 32)
  mstore(36, len)
  mstore(68, left)
  mstore(100, right)
  revert(0, 132)
}

function __revert_data(offset, size) {
  // Code Size: 18 (possibly 16)
  // https://docs.soliditylang.org/en/v0.8.20/control-structures.html#revert
  mstore(0, shl(224, 0x08c379a0)) // keccak256("Error(string)")
  mstore(4, 32)
  mstore(36, size)
  datacopy(68, offset, size)
  mstore(add(68, size), 0) // Pad.
  size := and(add(size, 31), not(31)) // Round up.
  revert(0, add(68, size))
}

function __revert_int(rc) {
  // Code Size: 6
  // https://docs.soliditylang.org/en/v0.8.20/control-structures.html#revert
  mstore(0, shl(224, 0xd7dad425)) // keccak256("ErrorCode(uint32)")
  mstore(4, rc)
  mstore(37, 0) // New Size: 8
  mstore(69, 0) // New Size: 10
  mstore(101, 0) // New Size: 12
  revert(0, 36)
}

function __panic(rc) {
  // Code Size: 6
  // https://docs.soliditylang.org/en/v0.8.20/control-structures.html
  // #panic-via-assert-and-error-via-require
  mstore(0, shl(224, 0x4e487b71)) // keccak256("Panic(uint256)")
  mstore(4, rc)
  mstore(37, 0) // New Size: 8
  mstore(69, 0) // New Size: 10
  mstore(101, 0) // New Size: 12
  revert(0, 36)
}

macro __panic_debug(rc) {
  @if defined(NDEBUG) {
    revert(0, 0)
  } else {
    __panic(rc)
  }
}

macro __require(ok) {
  // Code Size: 4
  if iszero(ok) {
    revert(0, 0)
  }
}

// Gas Cost: 15 + words(len) * 3 (+ CALL_GAS + 15)
function __mcopy(zp, xp, xn) {
  // Code Size: 13
  if iszero(or(eq(zp, xp), iszero(xn))) {
    __require(staticcall(gas(), 4, xp, xn, zp, xn))
  }
}

// Gas Cost: 33 + words(len) * 6
// 32 bytes = 39 gas, 64 bytes = 45 gas
// Code Size: 3 (+ 0-2)
macro __keccak160(xp, xn) :=
  and(keccak256(xp, xn), sub(shl(160, 1), 1))

// Code Size: 4-5 (+ 0-2)
// macro __keccak160(xp, xn) :=
//   shr(96, shl(96, keccak256(xp, xn)))

function __ripemd160_1(x) -> z {
  mstore(0, x)
  __ripemd160_3(0, 0, 32)
  z := mload(0)
}

function __sha256_1(x) -> z {
  mstore(0, x)
  __sha256_3(0, 0, 32)
  z := mload(0)
}

function __hash160_1(x) -> z {
  mstore(0, x)
  __hash160_3(0, 0, 32)
  z := mload(0)
}

function __hash256_1(x) -> z {
  mstore(0, x)
  __hash256_3(0, 0, 32)
  z := mload(0)
}

function __keccak160_1(x) -> z {
  mstore(0, x)
  z := __keccak160(0, 32)
}

function __keccak256_1(x) -> z {
  mstore(0, x)
  z := keccak256(0, 32)
}

function __ripemd160_2(xp, xn) -> z {
  __ripemd160_3(0, xp, xn)
  z := mload(0)
}

function __sha256_2(xp, xn) -> z {
  __sha256_3(0, xp, xn)
  z := mload(0)
}

function __hash160_2(xp, xn) -> z {
  __hash160_3(0, xp, xn)
  z := mload(0)
}

function __hash256_2(xp, xn) -> z {
  __hash256_3(0, xp, xn)
  z := mload(0)
}

function __keccak160_2(xp, xn) -> z {
  z := __keccak160(xp, xn)
}

// Gas Cost: 30 + words(len) * 6
// 32 bytes = 36 gas, 64 bytes = 42 gas
// function __keccak256_2(xp, xn) -> z {
//   z := keccak256(xp, xn)
// }

// Gas Cost: 600 + words(len) * 120 (+ CALL_GAS + 15)
// Base: 32 bytes = 720 gas, 64 bytes = 840 gas
// Tangerine: 32 bytes = 1435 gas, 64 bytes = 1555 gas
// Berlin: 32 bytes = 835 gas, 64 bytes = 955 gas
function __ripemd160_3(zp, xp, xn) {
  // Code Size: 8
  __require(staticcall(gas(), 3, xp, xn, zp, 32))
}

// Gas Cost: 60 + words(len) * 12 (+ CALL_GAS + 15)
// Base: 32 bytes = 72 gas, 64 bytes = 84 gas
// Tangerine: 32 bytes = 787 gas, 64 bytes = 799 gas
// Berlin: 32 bytes = 187 gas, 64 bytes = 199 gas
function __sha256_3(zp, xp, xn) {
  // Code Size: 8
  __require(staticcall(gas(), 2, xp, xn, zp, 32))
}

// Gas Cost: 60 + words(len) * 12 + 720 (+ CALL_GAS * 2 + 30)
// Base: 32 bytes = 792 gas, 64 bytes = 804 gas
// Tangerine: 32 bytes = 2222 gas, 64 bytes = 2234 gas
// Berlin: 32 bytes = 1022 gas, 64 bytes = 1034 gas
function __hash160_3(zp, xp, xn) {
  // Code Size: 17
  __require(staticcall(gas(), 2, xp, xn, zp, 32))
  __require(staticcall(gas(), 3, zp, 32, zp, 32))
}

// Gas Cost: 60 + words(len) * 12 + 72 (+ CALL_GAS * 2 + 30)
// Base: 32 bytes = 144 gas, 64 bytes = 156 gas, 10000 bytes = 3888
// Tangerine: 32 bytes = 1574 gas, 64 bytes = 1586 gas, 10000 bytes = 5318
// Berlin: 32 bytes = 374 gas, 64 bytes = 386 gas, 10000 bytes = 4118
function __hash256_3(zp, xp, xn) {
  // Code Size: 17
  __require(staticcall(gas(), 2, xp, xn, zp, 32))
  __require(staticcall(gas(), 2, zp, 32, zp, 32))
}

function __keccak160_3(zp, xp, xn) {
  mstore(zp, __keccak160(xp, xn))
}

function __keccak256_3(zp, xp, xn) {
  mstore(zp, keccak256(xp, xn))
}

// Gas Cost: rounds(input) (+ CALL_GAS + 15)
// Blake2b Cost: 12 (+ CALL_GAS + 15)
macro __blake2f(zp, xp) {
  // Code Size: 9
  __require(staticcall(gas(), 9, xp, 213, zp, 64))
}

macro __blake2b_iv1 :=
  0x08c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5

macro __blake2b_iv2 :=
  0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b

// Gas Cost: 166 + floor(len / 128) * 88
//        (+ (CALL_GAS + 15) + floor(len / 128) * (CALL_GAS + 15))
// Tangerine: 881 + floor(len / 128) * 803
// Berlin: 281 + floor(len / 128) * 203
// Base: <=128 bytes = 166 gas, 10000 bytes = 7030
// Tangerine: <=128 bytes = 881 gas, 10000 bytes = 63515
// Berlin: <=128 bytes = 281 gas, 10000 bytes = 16115
// Scratch requires 356 bytes (12 words, 384 bytes).
function __blake2b(zp, zn, xp, xn) {
  let s := add(add(xp, xn), 128)
  let r := add(s, 0) // rounds (4)
  let h := add(s, 4) // state (64)
  let m := add(s, 68) // message (128)
  let t := add(s, 196) // counter (16)
  let f := add(s, 212) // last block flag (1)

  mstore(r, shl(224, 12))
  mstore(add(h, 0),  xor(__blake2b_iv1, shl(248, zn)))
  mstore(add(h, 32), __blake2b_iv2)
  mstore(t, 0)

  {
    let end := add(xp, xn)
    mstore(add(end, 0), 0)
    mstore(add(end, 32), 0)
    mstore(add(end, 64), 0)
    mstore(add(end, 96), 0)
  }

  let ctr := 0

  while gt(xn, 128) {
    ctr := add(ctr, 128)

    mstore(add(m, 0), mload(add(xp, 0)))
    mstore(add(m, 32), mload(add(xp, 32)))
    mstore(add(m, 64), mload(add(xp, 64)))
    mstore(add(m, 96), mload(add(xp, 96)))

    mstore8(add(t, 0), shr(0, ctr))
    mstore8(add(t, 1), shr(8, ctr))
    mstore8(add(t, 2), shr(16, ctr))

    __blake2f(h, s)

    xp := add(xp, 128)
    xn := sub(xn, 128)
  }

  {
    ctr := add(ctr, xn)

    mstore(add(m, 0), mload(add(xp, 0)))
    mstore(add(m, 32), mload(add(xp, 32)))
    mstore(add(m, 64), mload(add(xp, 64)))
    mstore(add(m, 96), mload(add(xp, 96)))

    mstore8(add(t, 0), shr(0, ctr))
    mstore8(add(t, 1), shr(8, ctr))
    mstore8(add(t, 2), shr(16, ctr))

    mstore8(f, 1)

    __blake2f(h, s)
  }

  if gt(zn, 32) {
    let shift := sub(512, shl(3, zn))
    let h1 := mload(add(h, 0))
    let h2 := mload(add(h, 32))

    h2 := or(shl(sub(256, shift), h1), shr(shift, h2))
    h1 := shr(shift, h1)

    mstore(add(zp, 0), h1)
    mstore(add(zp, 32), h2)

    leave
  }

  const shift := sub(256, shl(3, zn))

  mstore(zp, shr(shift, mload(h)))
}

function __blake2b160_1(x) -> z {
  mstore(0, x)
  __blake2b(0, 20, 0, 32)
  z := mload(0)
}

function __blake2b160_2(xp, xn) -> z {
  __blake2b(0, 20, xp, xn)
  z := mload(0)
}

function __blake2b160_3(zp, xp, xn) {
  __blake2b(zp, 20, xp, xn)
}

function __blake2b256_1(x) -> z {
  mstore(0, x)
  __blake2b(0, 32, 0, 32)
  z := mload(0)
}

function __blake2b256_2(xp, xn) -> z {
  __blake2b(0, 32, xp, xn)
  z := mload(0)
}

function __blake2b256_3(zp, xp, xn) {
  __blake2b(zp, 32, xp, xn)
}

// Gas Cost: 3000 (+ CALL_GAS + 2)
macro __ecrecover(zp, xp) :=
  staticcall(gas(), 1, xp, 128, zp, 32)

// Gas Cost: 3702 (3102 after berlin)
function __ecrecover_2(zp, xp) -> ok {
  // input = (msg, param + 27, R, S)
  ok := __ecrecover(zp, xp)
}

// Gas Cost: 3765 (3165 after berlin)
function __ecrecover_4(msg_hash, sig_v, sig_r, sig_s) -> addr {
  // https://github.com/ethereum/go-ethereum/blob/8bbaf88/core/vm/contracts.go#L188
  // https://github.com/ethereum/go-ethereum/blob/8bbaf88/crypto/crypto.go#L262
  const nh := 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0

  if gt(sig_s, nh) {
    addr := 0
    leave
  }

  if or(lt(sig_v, 27), gt(sig_v, 28)) { // Probably not necessary.
    addr := 0
    leave
  }

  mstore(0, msg_hash)
  mstore(32, sig_v)
  mstore(64, sig_r)
  mstore(96, sig_s)
  mstore(128, 0)

  let ok := __ecrecover(128, 0)

  if iszero(ok) {
    addr := 0
    leave
  }

  addr := mload(128)
}

// Gas Cost: 3781 (3181 after berlin)
function __ecverify_5(msg_hash, sig_v, sig_r, sig_s, addr) -> ok {
  // Code Size: 7
  let result := __ecrecover_4(msg_hash, sig_v, sig_r, sig_s)

  switch result {
    case 0 {
      ok := 0
    }
    default {
      ok := eq(result, addr)
    }
  }
}

// Gas Cost: 3832 (3232 after berlin)
function __ecverify_6(msg_hash, sig_v, sig_r, sig_s, pub_x, pub_y) -> ok {
  // Code Size: 8
  mstore(0, pub_x)
  mstore(32, pub_y)

  let addr := __keccak160(0, 64)

  ok := __ecverify_5(msg_hash, sig_v, sig_r, sig_s, addr)
}
