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

fn keccakPad(msg: ByteArray, rateBytes: Int) -> ByteArray {
  // 填充规则：在 msg 后加 0x06，末尾字节 ^ 0x80，扩至整块
  let padded = msg.copy()
  let padLen = rateBytes - (msg.length() % rateBytes)

  []
}