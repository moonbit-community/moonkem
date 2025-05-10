///|
const Q = 3329

///|
/// BitsToBytes: bit 数组 → byte 数组
fn bits_to_bytes(bits : Array[Int], l : Int) -> ByteArray {
  let b : Array[Byte] = Array::make(l, 0x00)

  // 遍历每一个 bit
  for i in 0..<(8 * l) {
    // 目标字节下标 = ⌊i/8⌋
    let byte_idx = i / 8
    // bits[i] ∈ {0,1}，放到对应 bit 位上
    // 按照 2^(i mod 8) 的权重累加
    b[byte_idx] = (b[byte_idx].to_int() | (bits[i] << (i % 8))).to_byte()
  }
  b
}

///|
/// BytesToBits: byte 数组 → bit 数组
fn bytes_to_bits(b : ByteArray) -> Array[Int] {
  let l = b.length()
  // 拷贝一份，下面要不断除 2
  let c = b.copy()
  let bits = Array::make(8 * l, 0)
  for i in 0..<l {
    // 对 c[i] 做 8 次取余和整除
    for j in 0..<8 {
      bits[i * 8 + j] = c[i].to_int() % 2
      c[i] = (c[i].to_int() >> 1).to_byte()
    }
  }
  bits
}

///|
/// Compress_d: ℤ_q → ℤ_{2^d}
fn compress(x : Int, d : Int) -> Int {
  // 计算 y = ⌈ (2^d / q) * x ⌋ mod 2^d
  // 1) 先做左移：x * 2^d
  let numerator = x << d // 相当于 x * (1 << d)
  // 2) 整数除法：/(q) 会向下取整
  let y = numerator / Q // floor((2^d * x) / q)
  // 3) 再 mod 2^d
  let mask = (1 << d) - 1
  y & mask // 等价于 y mod 2^d
}

///| 
/// Decompress_d: ℤ_{2^d} → ℤ_q
fn decompress(y : Int, d : Int) -> Int {
  // numerator = q * y
  let numerator = y * Q // 整数运算
  // numerator / 2^d       // 整数除法自动地向下取整
  numerator / (1 << d)
}

///|
/// ByteEncode_d: 整数数组 F[0..255] → ByteArray (长 32*d)
fn byte_encode(f : Array[Int], d : Int) -> ByteArray {
  let bits = Array::make(256 * d, 0)

  // 将每个 F[i] （模 m）拆成 d bit
  for i in 0..<256 {
    let mut a = f[i] // 0 <= a < m
    for j in 0..<d {
      bits[i * d + j] = a % 2
      a = (a - bits[i * d + j]) >> 1
    }
  }

  // 再调用 bits_to_bytes 得到最终字节数组
  bits_to_bytes(bits, 256 * d / 8)
}

///|
/// ByteDecode_d: ByteArray → 整数数组 F[0..255]
fn byte_decode(b : ByteArray, d : Int) -> Array[Int] {
  // 先拆位
  let bits = bytes_to_bits(b)
  let f = Array::make(256, 0)

  // 每 d bit 合成一个整数，再 mod m
  let m = if d < 12 { 1 << d } else { 3329 }
  for i in 0..<256 {
    let mut value = 0
    for j in 0..<d {
      // bits[i * d + j] * 2 ^ j
      value += bits[i * d + j] * (1 << j)
    }
    f[i] = value % m
  }
  f
}
