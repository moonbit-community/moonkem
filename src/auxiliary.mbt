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

// Helper: Convert ByteArray slice to UInt64 (Little-Endian)
fn bytes_to_u64_le(bytes: ByteArray, offset: Int) -> UInt64 {
  var res: UInt64 = 0
  for i = 0; i < 8; i = i + 1 {
    if offset + i < bytes.length() {
      res = res | (bytes[offset + i].to_uint64() << (i * 8))
    }
  }
  res
}

// Helper: Convert UInt64 to ByteArray (Little-Endian)
fn u64_to_bytes_le(val: UInt64, output: ByteArray, offset: Int) -> Unit {
  for i = 0; i < 8; i = i + 1 {
    if offset + i < output.length() {
      output[offset + i] = ((val >> (i * 8)) & 0xFF).to_byte()
    }
  }
}

// Keccak absorb phase
fn keccak_absorb(state: Array[UInt64], input: ByteArray, rate_bytes: Int, pad_suffix: Byte) -> Unit {
  var offset = 0
  // Absorb full blocks
  while offset + rate_bytes <= input.length() {
    for i = 0; i < rate_bytes / 8; i = i + 1 {
      state[i] = state[i] ^ bytes_to_u64_le(input, offset + i * 8)
    }
    keccakF(state)
    offset = offset + rate_bytes
  }

  // Handle the last partial block and padding
  let remaining = input.length() - offset
  let last_block = Array::make(rate_bytes, 0.to_byte())

  // Copy remaining input bytes
  for i = 0; i < remaining; i = i + 1 {
    last_block[i] = input[offset + i]
  }

  // Apply padding: M || suffix || 10*1
  last_block[remaining] = pad_suffix // Append suffix (0x06 for SHA3, 0x1F for SHAKE)
  last_block[rate_bytes - 1] = last_block[rate_bytes - 1] | 0x80.to_byte() // Set the last bit of the rate part

  // XOR the padded block into the state
  for i = 0; i < rate_bytes / 8; i = i + 1 {
     state[i] = state[i] ^ bytes_to_u64_le(last_block, i * 8)
  }

  // Final permutation
  keccakF(state)
}

// Keccak squeeze phase
fn keccak_squeeze(state: Array[UInt64], output: ByteArray, output_len_bytes: Int, rate_bytes: Int) -> Unit {
  var produced = 0
  let state_bytes = Array::make(200, 0.to_byte()) // 1600 bits = 200 bytes

  while produced < output_len_bytes {
    // Convert state lanes to bytes
    for i = 0; i < 25; i = i + 1 {
      u64_to_bytes_le(state[i], state_bytes, i * 8)
    }

    // Copy rate portion to output
    let count = Int::min(rate_bytes, output_len_bytes - produced)
    for i = 0; i < count; i = i + 1 {
      output[produced + i] = state_bytes[i]
    }
    produced = produced + count

    // If more output is needed, run KeccakF again
    if produced < output_len_bytes {
      keccakF(state)
    }
  }
}

/// SHA3-256 hash function
fn sha3_256(input: ByteArray) -> ByteArray {
  var state = Array::make(25, 0) // Initialize state to all zeros
  let output = Array::make(sha3_256_DIGEST_SIZE, 0.to_byte())

  keccak_absorb(state, input, KECCAK_RATE_sha3_256, SHA3_PAD_SUFFIX)
  keccak_squeeze(state, output, sha3_256_DIGEST_SIZE, KECCAK_RATE_sha3_256)

  output
}

/// SHA3-512 hash function
fn sha3_512(input: ByteArray) -> ByteArray {
  var state = Array::make(25, 0)
  let output = Array::make(sha3_512_DIGEST_SIZE, 0.to_byte())

  keccak_absorb(state, input, KECCAK_RATE_sha3_512, SHA3_PAD_SUFFIX)
  keccak_squeeze(state, output, sha3_512_DIGEST_SIZE, KECCAK_RATE_sha3_512)

  output
}

/// shake128 extendable-output function
fn shake128(input: ByteArray, output_len_bytes: Int) -> ByteArray {
  var state = Array::make(25, 0)
  let output = Array::make(output_len_bytes, 0.to_byte())

  keccak_absorb(state, input, KECCAK_RATE_SHAKE128, SHAKE_PAD_SUFFIX)
  keccak_squeeze(state, output, output_len_bytes, KECCAK_RATE_SHAKE128)

  output
}

/// shake256 extendable-output function
fn shake256(input: ByteArray, output_len_bytes: Int) -> ByteArray {
  var state = Array::make(25, 0)
  let output = Array::make(output_len_bytes, 0.to_byte())

  keccak_absorb(state, input, KECCAK_RATE_SHAKE256, SHAKE_PAD_SUFFIX)
  keccak_squeeze(state, output, output_len_bytes, KECCAK_RATE_SHAKE256)

  output
}

/// Simple prf based on shake256: prf(K, X) = shake256(K || X, L)
/// K: Key (ByteArray)
/// X: Input (ByteArray)
/// output_len_bytes: Desired output length in bytes
fn prf(key: ByteArray, input: ByteArray, output_len_bytes: Int) -> ByteArray {
  // Concatenate key and input
  let combined_input = Array::make(key.length() + input.length(), 0.to_byte())
  for i = 0; i < key.length(); i = i + 1 {
    combined_input[i] = key[i]
  }
  for i = 0; i < input.length(); i = i + 1 {
    combined_input[key.length() + i] = input[i]
  }

  // Use shake256 on the combined input
  shake256(combined_input, output_len_bytes)
}

// Example Usage (Optional - for testing)
  test {
  let msg = "hello".to_bytes()
  let hash256 = sha3_256(msg)
  let hash512 = sha3_512(msg)
  let shake128_out = shake128(msg, 64) // Get 64 bytes output
  let shake256_out = shake256(msg, 64) // Get 64 bytes output

  let key = "mysecretkey".to_bytes()
  let data = "somedata".to_bytes()
  let prf_out = prf(key, data, 32) // Get 32 bytes prf output

  println("SHA3-256:")
  for b in hash256 { print(b.to_hex_string()) }
  println("")

  println("SHA3-512:")
  for b in hash512 { print(b.to_hex_string()) }
  println("")

  println("shake128 (64 bytes):")
  for b in shake128_out { print(b.to_hex_string()) }
  println("")

  println("shake256 (64 bytes):")
  for b in shake256_out { print(b.to_hex_string()) }
  println("")

  println("prf (32 bytes):")
  for b in prf_out { print(b.to_hex_string()) }
  println("")

  0
}

/// Simple prf based on shake256: prf(K, X) = shake256(K || X, L)
/// K: Key (ByteArray)
/// X: Input (ByteArray)
/// output_len_bytes: Desired output length in bytes
fn prf(key: ByteArray, input: ByteArray, output_len_bytes: Int) -> ByteArray {
  // Concatenate key and input
  let combined_input = Array::make(key.length() + input.length(), 0.to_byte())
  for i = 0; i < key.length(); i = i + 1 {
    combined_input[i] = key[i]
  }
  for i = 0; i < input.length(); i = i + 1 {
    combined_input[key.length() + i] = input[i]
  }

  // Use shake256 on the combined input
  shake256(combined_input, output_len_bytes)
}

/// Hash function H (based on SHA3-256)
/// Input: ByteArray
/// Output: 32-byte ByteArray (SHA3-256 hash)
fn H(input: ByteArray) -> ByteArray {
  sha3_256(input)
}

/// Hash function J (based on shake256)
/// Input: ByteArray
/// output_len_bytes: Desired output length in bytes
/// Output: ByteArray of specified length
fn J(input: ByteArray, output_len_bytes: Int) -> ByteArray {
  shake256(input, output_len_bytes)
}

/// Hash function G (based on SHA3-512, split output)
/// Input: ByteArray
/// Output: Tuple of two 32-byte ByteArrays (SHA3-512 hash split in half)
fn G(input: ByteArray) -> (ByteArray, ByteArray) {
  let hash512 = sha3_512(input) // 64 bytes output
  let output1 = Array::make(32, 0.to_byte())
  let output2 = Array::make(32, 0.to_byte())

  // Split the 64-byte hash into two 32-byte arrays
  for i = 0; i < 32; i = i + 1 {
    output1[i] = hash512[i]
    output2[i] = hash512[i + 32]
  }

  (output1, output2)
}


// Example Usage (Optional - for testing)
  test {
  let msg = "hello".to_bytes()
  let hash_h = H(msg)
  let (hash_g1, hash_g2) = G(msg)
  let hash_j = J(msg, 64) // Get 64 bytes output

  let key = "mysecretkey".to_bytes()
  let data = "somedata".to_bytes()
  let prf_out = prf(key, data, 32) // Get 32 bytes prf output

  println("H (SHA3-256):")
  for b in hash_h { print(b.to_hex_string()) }
  println("")

  println("G (SHA3-512 split):")
  print("Part 1: ")
  for b in hash_g1 { print(b.to_hex_string()) }
  println("")
  print("Part 2: ")
  for b in hash_g2 { print(b.to_hex_string()) }
  println("")

  println("J (shake256, 64 bytes):")
  for b in hash_j { print(b.to_hex_string()) }
  println("")

  println("prf (32 bytes):")
  for b in prf_out { print(b.to_hex_string()) }
  println("")

  0
}