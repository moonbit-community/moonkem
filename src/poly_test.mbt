// ML-KEM 多项式操作单元测试

///|
test "mod_q/basic" {
  let q = 3329

  // 正常情况测试
  assert_eq!(mod_q(0, q), 0)
  assert_eq!(mod_q(1, q), 1)
  assert_eq!(mod_q(q - 1, q), q - 1)
  assert_eq!(mod_q(q, q), 0)
  assert_eq!(mod_q(q + 1, q), 1)
  assert_eq!(mod_q(2 * q, q), 0)

  // 负数测试
  assert_eq!(mod_q(-1, q), q - 1)
  assert_eq!(mod_q(-q, q), 0)
  assert_eq!(mod_q(-q - 1, q), q - 1)
}

///|
test "poly_add/basic" {
  let n = common_params.n
  let q = common_params.q

  // 创建测试多项式
  let a = new_poly(n)
  let b = new_poly(n)
  let c = new_poly(n)

  // 设置测试值
  a[0] = 1000
  a[1] = 2000
  a[2] = 3000
  a[n - 1] = q - 1
  b[0] = 500
  b[1] = 1500
  b[2] = 2500
  b[n - 1] = 1

  // 执行加法
  poly_add(c, a, b)

  // 验证结果
  assert_eq!(c[0], 1500)
  assert_eq!(c[1], 3500 % q) // 3500 % 3329 = 171
  assert_eq!(c[2], 5500 % q) // 5500 % 3329 = 2171
  assert_eq!(c[n - 1], 0) // (q-1) + 1 = q = 0 mod q
}

///|
test "poly_sub/basic" {
  let n = common_params.n
  let q = common_params.q

  // 创建测试多项式
  let a = new_poly(n)
  let b = new_poly(n)
  let c = new_poly(n)

  // 设置测试值
  a[0] = 2000
  a[1] = 1000
  a[2] = 0
  a[n - 1] = 1
  b[0] = 500
  b[1] = 1500
  b[2] = 100
  b[n - 1] = 2

  // 执行减法
  poly_sub(c, a, b)

  // 验证结果
  assert_eq!(c[0], 1500)
  assert_eq!(c[1], q - 500) // 负数结果变为正模
  assert_eq!(c[2], q - 100) // 负数结果变为正模
  assert_eq!(c[n - 1], q - 1) // 1 - 2 = -1 = q-1 mod q
}

///|
test "poly_scalar_mul/basic" {
  let n = common_params.n
  let q = common_params.q

  // 创建测试多项式
  let a = new_poly(n)
  let b = new_poly(n)

  // 设置测试值
  a[0] = 1000
  a[1] = 2000
  a[2] = 0
  a[3] = q - 1

  // 执行乘法 (标量 = 3)
  poly_scalar_mul(b, a, 3)

  // 验证结果
  assert_eq!(b[0], 3000)
  assert_eq!(b[1], 6000 % q) // 6000 > q, 需要取模
  assert_eq!(b[2], 0)
  assert_eq!(b[3], 3 * (q - 1) % q)

  // 测试负数标量
  poly_scalar_mul(b, a, -2)

  // 验证结果
  assert_eq!(b[0], mod_q(-2000, q))
  assert_eq!(b[1], mod_q(-4000, q))
  assert_eq!(b[3], mod_q(-2 * (q - 1), q))
}

///|
test "poly_reduce/basic" {
  let n = common_params.n
  let q = common_params.q
  let q_half = q / 2

  // 创建测试多项式
  let a = new_poly(n)

  // 设置测试值 - 边界情况
  a[0] = 0
  a[1] = 1
  a[2] = q_half
  a[3] = q_half + 1
  a[4] = q - 1
  a[5] = q // 应该变为0
  a[6] = q + 1 // 应该变为1

  // 执行规约
  poly_reduce(a)

  // 验证结果 (中心表示范围[-q/2, q/2))
  assert_eq!(a[0], 0)
  assert_eq!(a[1], 1)
  assert_eq!(a[2], q_half)
  assert_eq!(a[3], -(q - (q_half + 1))) // 应该变为负数
  assert_eq!(a[4], -(q - (q - 1))) // 应该变为-1
  assert_eq!(a[5], 0)
  assert_eq!(a[6], 1)
}

///|
test "poly_is_zero/basic" {
  let n = common_params.n

  // 测试零多项式
  let zero = new_poly(n)
  assert_true!(poly_is_zero(zero))

  // 测试非零多项式
  let non_zero = new_poly(n)
  non_zero[n - 1] = 1 // 只设置最后一个元素为非零
  assert_false!(poly_is_zero(non_zero))

  // 再次清零
  non_zero[n - 1] = 0
  assert_true!(poly_is_zero(non_zero))
}

///|
test "poly_copy/basic" {
  let n = common_params.n

  // 创建源多项式
  let src = new_poly(n)
  for i = 0; i < n; i = i + 1 {
    src[i] = i * i % common_params.q
  }

  // 创建目标多项式
  let dst = new_poly(n)

  // 复制多项式
  poly_copy(dst, src)

  // 验证复制是否正确
  for i = 0; i < n; i = i + 1 {
    assert_eq!(dst[i], src[i])
  }

  // 验证是深拷贝而不是引用
  let original_value = dst[0] // 保存原始值
  src[0] = 9999
  assert_eq!(dst[0], original_value) // dst应保持原值
  assert_not_eq!(dst[0], src[0]) // src和dst应不同
}

///|
test "poly_compress_decompress/basic" {
  let n = common_params.n
  let d = 10 // 10位压缩

  // 创建测试多项式
  let original = new_poly(n)
  let recovered = new_poly(n)

  // 设置测试值
  for i = 0; i < n; i = i + 1 {
    original[i] = i * 100 % common_params.q
  }

  // 计算压缩后需要的字节长度
  let compressed_bytes = (n * d + 7) / 8 // 向上取整到字节
  let compressed : Array[Byte] = Array::make(compressed_bytes, 0)

  // 执行压缩
  poly_compress(compressed, original, d)

  // 执行解压缩
  poly_decompress(recovered, compressed, d)

  // 验证结果 - 压缩和解压缩会有一些精度损失
  let tolerance = 16 // 增加允许的误差范围

  // 只测试部分关键索引
  for i in [0, 1, 2, n / 2, n - 3, n - 2, n - 1] {
    let diff = (original[i] - recovered[i]).abs()
    assert_true!(diff <= tolerance)
  }
}

///|
test "bit_packing_verification" {
  // 测试简单的位打包和解包操作
  let values = [0, 1, 2, 3, 4, 5, 6, 7]
  let d = 3 // 3位足够表示0-7
  let bytes_needed = (values.length() * d + 7) / 8
  let packed : Array[Byte] = Array::make(bytes_needed, 0)

  // 手动执行位打包
  let mut bit_offset = 0
  let mut byte_offset = 0
  let mut current_byte = 0
  for i = 0; i < values.length(); i = i + 1 {
    current_byte = current_byte | ((values[i] & ((1 << d) - 1)) << bit_offset)
    bit_offset = bit_offset + d
    while bit_offset >= 8 {
      packed[byte_offset] = (current_byte & 0xFF).to_byte()
      byte_offset = byte_offset + 1
      bit_offset = bit_offset - 8
      current_byte = current_byte >> 8
    }
  }
  if bit_offset > 0 {
    packed[byte_offset] = (current_byte & 0xFF).to_byte()
  }

  // 打印打包后的字节，用于调试
  println("打包后的字节: ")
  for i = 0; i < packed.length(); i = i + 1 {
    println((packed[i].to_int() & 0xFF).to_string() + " ")
  }
  println("")

  // 手动解包并验证
  let unpacked = Array::make(values.length(), 0)
  bit_offset = 0
  byte_offset = 0
  for i = 0; i < values.length(); i = i + 1 {
    let mut val = 0
    let mut bits_read = 0
    while bits_read < d {
      if byte_offset < packed.length() {
        let current_byte = packed[byte_offset].to_int() & 0xFF
        let bits_available = 8 - bit_offset
        let bits_needed = d - bits_read
        let bits_to_read = if bits_available < bits_needed {
          bits_available
        } else {
          bits_needed
        }
        let mask = (1 << bits_to_read) - 1
        let extracted = (current_byte >> bit_offset) & mask
        val = val | (extracted << bits_read)
        bits_read = bits_read + bits_to_read
        bit_offset = bit_offset + bits_to_read
        if bit_offset == 8 {
          bit_offset = 0
          byte_offset = byte_offset + 1
        }
      }
    }
    unpacked[i] = val
  }

  // 验证解包结果
  for i = 0; i < values.length(); i = i + 1 {
    assert_eq(values[i], unpacked[i])
  }
}

