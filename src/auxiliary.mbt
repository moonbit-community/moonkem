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
struct XOF_CTX {
  state : Array[UInt64]
  buf : ByteArray
  mut squeezed : Bool
}

///|
pub fn to_uint64(bytes : ByteArray) -> UInt64 {
  let mut result : UInt64 = 0
  for i = 0; i < 8; i = i + 1 {
    let part = bytes[i].to_uint64() << (8 * i)
    result = result | part
  }
  result
}

///|
pub fn from_uint64(x : UInt64) -> ByteArray {
  let out : ByteArray = Array::make(8, 0)
  for i = 0; i < 8; i = i + 1 {
    out[i] = ((x >> (8 * i)) & 0xFF).to_byte()
  }
  out
}

///|
pub fn rotl(x : UInt64, n : Int) -> UInt64 {
  ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
}

///|
pub fn bitwise_not(x : UInt64) -> UInt64 {
  return x ^ ALL_ONES_64
}

///| Keccak-f 置换函数（核心哈希运算）
///
/// Parameters
///
/// - `state` : 一个长度为 25 的 UInt64 数组，表示 5x5 的 Keccak 状态矩阵。
///
/// Returns
///
/// - `Unit` : 此函数无返回值，直接在输入的状态数组上进行原地修改。
///
/// Errors
///
/// - 无显式错误抛出（但需要确保输入数组长度为 25）。
///
/// Description
///
/// Keccak-f 是 Keccak 哈希算法（SHA-3 的核心）的置换函数。它对输入的 5x5 状态矩阵进行一系列回合（rounds）操作，每一回合包括以下 5 个步骤：
///
/// 1. θ (Theta)：列间异或和扩散，生成中间数组 c 和 d，并对状态进行修正；
/// 2. ρ (Rho) 与 π (Pi)：位移操作和位置重新排列，将状态扩散到矩阵的其它位置；
/// 3. χ (Chi)：行内非线性混淆，增强安全性；
/// 4. ι (Iota)：加上回合常数，打破对称性。
///
/// 本实现按照标准流程原地修改输入状态。
pub fn keccakF(state : Array[UInt64]) -> Unit {
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

///| Keccak 消息填充函数（Keccak/SHA-3 专用）
///
/// Parameters
///
/// - `msg` : 原始消息字节数组（ByteArray）
/// - `rateBytes` : 块长度，单位为字节。一般为 Keccak 的速率参数（如 136/104）
/// - `padByte` : 填充起始字节（通常为 0x06 或 0x01，根据标准不同）
///
/// Returns
///
/// - `ByteArray` : 填充后的新字节数组，长度为 rateBytes 的整数倍
///
/// Errors
///
/// - 无显式错误抛出，但请确保参数含义正确
///
/// Description
///
/// 按 Keccak（SHA-3）标准对输入消息进行填充：
/// 1. 首先在消息末尾追加 `padByte`（例如 0x06）
/// 2. 用零字节（0x00）补齐至下一个 `rateBytes` 整数倍长度
/// 3. 最后一个字节再异或 0x80，确保填充末尾为 1
///
/// 这种填充方式被称为 "multi-rate padding"（多速率填充），用于确保数据块边界，保证安全性。
///
/// Example
/// ```
/// let padded = keccakPad(msg, 136, 0x06)
/// ```
pub fn keccakPad(msg : ByteArray, rateBytes : Int, padByte : Byte) -> ByteArray {
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

///| Keccak 海绵函数主流程（Sponge Construction）
///
/// Parameters
///
/// - `msg` : 输入消息字节数组（ByteArray）
/// - `rateBytes` : 吸收/输出阶段的速率参数（单位：字节），决定每轮处理的消息块大小
/// - `outLen` : 期望输出的摘要字节长度
/// - `padByte` : 填充起始字节（通常为 0x06 或 0x01）
///
/// Returns
///
/// - `ByteArray` : 长度为 `outLen` 的输出字节数组（摘要）
///
/// Errors
///
/// - 无显式错误抛出，但需确保参数合法（如 `rateBytes` 是 8 的整数倍）
///
/// Description
///
/// 实现 Keccak 的 Sponge 结构，是 SHA-3 及 Keccak 哈希算法的核心：
///
/// 1. **初始化状态**：创建长度为 25 的 64 位整型数组作为状态（5x5 矩阵）
/// 2. **填充消息**：使用 Keccak 标准填充（multi-rate padding）
/// 3. **吸收阶段（Absorbing phase）**：
///    - 每次取 `rateBytes` 长度的数据块，与状态前部进行异或合并
///    - 每处理一块调用一次 Keccak-f 置换函数
/// 4. **挤出阶段（Squeezing phase）**：
///    - 每次输出 `rateBytes` 字节，若未满足 `outLen` 则继续调用 Keccak-f 并拼接输出
///
/// 这种结构保证了任意长度输入消息的安全哈希摘要输出，是现代哈希标准（如 SHA-3）的基础。
///
/// Example
/// ```
/// let digest = keccakSponge(msg, 136, 32, 0x06)
/// ```
pub fn keccakSponge(
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
      let lane = to_uint64(laneBytes)
      state[i] = state[i] ^ lane
    }
    keccakF(state)
  }
  let output : ByteArray = Array::new()
  while output.length() < outLen {
    for i = 0; i < rateBytes / 8; i = i + 1 {
      let bytes = from_uint64(state[i])
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
pub fn shake256(msg : ByteArray, outLen : Int) -> ByteArray {
  keccakSponge(msg, 136, outLen, 0x1F)
}

///|
/// H(s) := SHA3-256(s)
pub fn h(s : ByteArray) -> ByteArray {
  sha3_256(s)
}

///|
/// J(s) := SHAKE256(s, 32)
pub fn j(s : ByteArray) -> ByteArray {
  shake256(s, 32)
}

///|
/// G(c) := SHA3-512(c) = (a, b)
pub fn g(c : ByteArray) -> (ByteArray, ByteArray) {
  let full = sha3_512(c)
  full.split_at(31)
}

///| PRF_η(s, b) := SHAKE256(s || b, 64 * η)
pub fn prf(eta : Int, s : ByteArray, b : Byte) -> ByteArray {
  let input = s.copy()
  input.push(b)
  shake256(input, 64 * eta)
}

///|
/// 连接两个字节数组
/// @param a 第一个字节数组
/// @param b 第二个字节数组
/// @return 合并后的字节数组
pub fn concat_bytes(a : ByteArray, b : ByteArray) -> ByteArray {
  let result = a.copy()
  result.append(b)
  result
}

///|
/// 比较两个字节数组是否相等（常时间比较）
/// @param a 第一个字节数组
/// @param b 第二个字节数组
/// @return 是否相等
pub fn constant_time_compare(a : ByteArray, b : ByteArray) -> Bool {
  // 如果长度不同，立即返回false
  if a.length() != b.length() {
    return false
  }

  // 初始化差异变量为0字节
  let mut diff : Byte = 0

  // 常时间比较：遍历所有字节并累积差异（不会在找到第一个不同处就返回）
  for i = 0; i < a.length(); i = i + 1 {
    // 使用按位异或检测差异，并用按位或累积
    diff = diff | (a[i] ^ b[i])
  }

  // 只有当所有字节都相同（即diff为0）时才返回true
  return diff == 0
}

///|
/// 字节数组转Int数组（用于多项式表示）
/// @param bytes 输入字节数组
/// @param mod_value 模数值（如ML-KEM中的q=3329）
/// @return 输出Int数组，每个元素是小于mod_value的整数
pub fn bytes_to_ints(bytes : ByteArray, mod_value : Int) -> Array[Int] {
  let result = Array::new()

  // 确定我们能从输入字节中提取多少个整数
  // 在ML-KEM中，通常每12位表示一个多项式系数（因为q=3329需要最多12位）
  let bits_per_int = bit_length(mod_value - 1)
  let total_bits = bytes.length() * 8
  let total_ints = total_bits / bits_per_int

  // 临时变量，用于跨字节边界累积位
  let mut bit_pos = 0
  let mut current_byte_idx = 0
  let mut current_byte = bytes[0].to_int()
  for _ in 0..<total_ints {
    let mut value = 0
    let mut bits_collected = 0

    // 收集足够的位以形成一个多项式系数
    while bits_collected < bits_per_int {
      // 当前字节中还可用的位数
      let bits_remaining_in_byte = 8 - bit_pos

      // 确定要从当前字节中获取多少位
      let bits_to_read = @math.minimum(
        bits_remaining_in_byte,
        bits_per_int - bits_collected,
      )

      // 从当前字节读取位
      // 首先右移移除不需要的低位，然后用掩码提取需要的位
      let mask = (1 << bits_to_read) - 1
      let extracted_bits = (current_byte >> bit_pos) & mask

      // 将这些位添加到当前值中
      value = value | (extracted_bits << bits_collected)
      bits_collected = bits_collected + bits_to_read

      // 更新位位置
      bit_pos = bit_pos + bits_to_read

      // 如果已经读完当前字节，移到下一个字节
      if bit_pos == 8 {
        bit_pos = 0
        current_byte_idx = current_byte_idx + 1
        if current_byte_idx < bytes.length() {
          current_byte = bytes[current_byte_idx].to_int()
        }
      }
    }

    // 应用模数
    value = value % mod_value

    // 添加到结果数组
    result.push(value)
  }
  return result
}

///|
/// 计算整数的二进制位长度
/// @param n 一个整数
/// @return 表示该整数所需的最小位数
pub fn bit_length(n : Int) -> Int {
  if n == 0 {
    return 1 // 0需要1位表示
  }
  let mut count = 0
  let mut value = n
  while value > 0 {
    count = count + 1
    value = value >> 1
  }
  return count
}

///|
/// SHAKE128 初始化
pub fn xof_init() -> XOF_CTX {
  { state: Array::make(25, 0), buf: [], squeezed: false }
}

///|
/// SHAKE128 吸收数据
pub fn absorb_block(ctx : XOF_CTX) -> Unit {
  for lane = 0; lane < 168 / 8; lane = lane + 1 {
    let mut t : UInt64 = 0
    for b = 0; b < 8; b = b + 1 {
      t = t | (ctx.buf[lane * 8 + b].to_uint64() << (8 * b))
    }
    ctx.state[lane] = ctx.state[lane] ^ t
  }
  keccakF(ctx.state)
  ctx.buf.clear()
}

///| SHAKE128 挤出输出
pub fn shake128_squeeze(ctx : XOF_CTX, out_len : Int) -> (XOF_CTX, ByteArray) {
  if not(ctx.squeezed) {
    // 填充：0x1F，最后一字节 ^ 0x80
    ctx.buf.push(0x1F)
    while ctx.buf.length() < 168 - 1 {
      ctx.buf.push(0x00)
    }
    ctx.buf.push(0x80)
    absorb_block(ctx)
    ctx.squeezed = true
  }
  let output : ByteArray = []
  while output.length() < out_len {
    for lane = 0; lane < 168 / 8; lane = lane + 1 {
      for b = 0; b < 8; b = b + 1 {
        if output.length() < out_len {
          let byte : Byte = (ctx.state[lane] >> (8 * b)).to_byte() & 0xFF
          output.push(byte)
        }
      }
    }
    if output.length() < out_len {
      keccakF(ctx.state)
    }
  }
  (ctx, output)
}

///|
pub fn xof_absorb(ctx : XOF_CTX, data : ByteArray) -> XOF_CTX {
  for i = 0; i < data.length(); i = i + 1 {
    ctx.buf.push(data[i])
    if ctx.buf.length() == 168 {
      absorb_block(ctx)
    }
  }
  ctx
}

///|
pub fn xof_squeeze(ctx : XOF_CTX, out_len : Int) -> (XOF_CTX, ByteArray) {
  if not(ctx.squeezed) {
    ctx.buf.push(0x1F)
    while ctx.buf.length() < 168 - 1 {
      ctx.buf.push(0x00)
    }
    ctx.buf.push(0x80)
    absorb_block(ctx)
    ctx.squeezed = true
  }
  let output : ByteArray = []
  while output.length() < out_len {
    for lane = 0; lane < 168 / 8; lane = lane + 1 {
      for b = 0; b < 8; b = b + 1 {
        if output.length() < out_len {
          let byte : Byte = (ctx.state[lane] >> (8 * b)).to_byte() & 0xFF
          output.push(byte)
        }
      }
    }
    if output.length() < out_len {
      keccakF(ctx.state)
    }
  }
  (ctx, output)
}
