///|
typealias ByteArray = Array[Byte]

///|
const ALL_ONES_64 : UInt64 = 0xFFFFFFFFFFFFFFFF

///| const
///| 
let w = 64

///| 
let b = 1600

///|
let nr = 24

///|
let r = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
]

///|
let rc : Array[UInt64] = [
  0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
  0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
  0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

///|
fn toUInt64(bytes : ByteArray) -> UInt64 {
  let mut result : UInt64 = 0
  for i = 0; i < 8; i = i + 1 {
    let part = bytes[i].to_uint64() << (8 * i)
    result = result | part
  }
  result
}

///|
test "toUInt64/zero" {
  let bytes = Array::make(8, b'\x00')
  inspect!(toUInt64(bytes), content="0")
}

///|
test "toUInt64/basic" {
  let bytes = [
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08',
  ]
  // Should represent 0x0807060504030201 in little-endian
  inspect!(toUInt64(bytes), content="578437695752307201")
}

///|
fn fromUInt64(x : UInt64) -> ByteArray {
  let out : ByteArray = Array::make(8, 0)
  for i = 0; i < 8; i = i + 1 {
    out[i] = ((x >> (8 * i)) & 0xFF).to_byte()
  }
  out
}
///|
test "fromUInt64/basic" {
  let input : UInt64 = 578437695752307201 // 0x0807060504030201
  let expected = [
    b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08',
  ]
  let result = fromUInt64(input)
  for i = 0; i < 8; i = i + 1 {
    inspect!(result[i], content="\{expected[i]}")
  }
}

///|
fn rotl(x : UInt64, n : Int) -> UInt64 {
  ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
}

///|
fn bitwise_not(x : UInt64) -> UInt64 {
  return x ^ ALL_ONES_64
}

///|
fn keccakF(state : Array[UInt64]) -> Unit {
  for round in 0..<nr {
    // ——— θ 步 ———
    let c = Array::new(capacity=5)
    for x in 0..<5 {
      c[x] = state[x] ^
        state[x + 5] ^
        state[x + 10] ^
        state[x + 15] ^
        state[x + 20]
    }
    let d = Array::new(capacity=5)
    for x in 0..<5 {
      d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
    }
    for x in 0..<5 {
      for y in 0..<5 {
        state[x + 5 * y] = state[x + 5 * y] ^ d[x]
      }
    }

    // ——— ρ 与 π 步 ———
    let b = Array::new(capacity=25)
    for x in 0..<5 {
      for y in 0..<5 {
        let newx = y
        let newy = (2 * x + 3 * y) % 5
        let idxSrc = x + 5 * y
        let idxDst = newx + 5 * newy
        b[idxDst] = rotl(state[idxSrc], r[x][y])
      }
    }
    for i in 0..<25 {
      state[i] = b[i]
    }

    // ——— χ 步 ———
    for y in 0..<5 {
      let row = Array::new(capacity=5)
      for x in 0..<5 {
        row[x] = state[x + 5 * y]
      }
      for x in 0..<5 {
        state[x + 5 * y] = row[x] ^
          (bitwise_not(row[(x + 1) % 5]) & row[(x + 2) % 5])
      }
    }

    // ——— ι 步 ———
    state[0] = state[0] ^ rc[round]
  }
}

///|
fn keccakPad(msg : ByteArray, rateBytes : Int, padByte : Byte) -> ByteArray {
  // 填充规则：在 msg 后加 0x06，末尾字节 ^ 0x80，扩至整块
  let msgLen = msg.length()
  let padLen = rateBytes - msgLen % rateBytes
  let block : ByteArray = Array::make(padLen, 0x00)
  block[0] = padByte
  block[padLen - 1] = block[padLen - 1] ^ 0x80
  let padded = msg.copy()
  padded.append(block)
  return padded
}

///|
fn keccakSponge(
  msg : ByteArray,
  rateBytes : Int,
  outLen : Int,
  padByte : Byte
) -> ByteArray {
  let state : Array[UInt64] = Array::make(25, 0)
  let padded = keccakPad(msg, rateBytes, padByte)
  for offset = 0; offset < padded.length(); offset = offset + rateBytes {
    for i = 0; i < rateBytes / 8; i = i + 1 {
      let laneBytes : ByteArray = Array::make(8, 0)
      for j = 0; j < 8; j = j + 1 {
        laneBytes[j] = padded[offset + i * 8 + j]
      }
      let lane = toUInt64(laneBytes)
      state[i] = state[i] ^ lane
    }
    keccakF(state)
  }
  let output : ByteArray = Array::new()
  while output.length() < outLen {
    for i = 0; i < rateBytes / 8; i = i + 1 {
      let bytes = fromUInt64(state[i])
      for j = 0; j < 8; j = j + 1 {
        if output.length() < outLen {
          output.push(bytes[j])
        }
      }
    }
    if output.length() < outLen {
      keccakF(state)
    }
  }
  output
}

///|
/// SHA3-256：固定输出 32 字节
pub fn sha3_256(msg : ByteArray) -> ByteArray {
  keccakSponge(msg, 136, 32, 0x06) // rate = 1088 bits = 136 bytes
}

///|
/// SHA3-512：固定输出 64 字节
pub fn sha3_512(msg : ByteArray) -> ByteArray {
  keccakSponge(msg, 72, 64, 0x06) // rate = 576 bits = 72 bytes
}

///|
/// SHAKE128：可变输出（比如 PRF、种子扩展）
pub fn shake128(msg : ByteArray, outLen : Int) -> ByteArray {
  keccakSponge(msg, 168, outLen, 0x1F)
}

///|
/// SHAKE256：可变输出（比如 PRF、KDF）
fn shake256(msg : ByteArray, outLen : Int) -> ByteArray {
  keccakSponge(msg, 136, outLen, 0x1F)
}

///|
/// H(s) := SHA3-256(s)
pub fn h(s : ByteArray) -> ByteArray {
  sha3_256(s)
}

///|
/// J(s) := SHAKE256(s, 32)
fn j(s : ByteArray) -> ByteArray {
  shake256(s, 32)
}

///|
/// G(c) := SHA3-512(c) = (a, b)
fn g(c : ByteArray) -> (ByteArray, ByteArray) {
  let full = sha3_512(c)
  full.split_at(31)
}

///| PRF_η(s, b) := SHAKE256(s || b, 64 * η)
fn prf(eta : Int, s : ByteArray, b : Byte) -> ByteArray {
  let input = s.copy()
  input.push(b)
  shake256(input, 64 * eta)
}
