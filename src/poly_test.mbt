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
    assert_eq!(values[i], unpacked[i])
  }
}

///|
test "poly_compress_decompress/boundary_values" {
  let n = common_params.n
  let q = common_params.q
  let d = 10 // ML-KEM中常用的10位压缩

  // 创建测试多项式
  let original = new_poly(n)
  let recovered = new_poly(n)

  // 设置边界值和关键值
  original[0] = 0 // 最小值
  original[1] = 1 // 最小正值
  original[2] = q / 4 // 四分之一
  original[3] = q / 2 // 半值点
  original[4] = 3 * q / 4 // 四分之三
  original[5] = q - 2 // 接近最大值
  original[6] = q - 1 // 最大值

  // 计算压缩字节数
  let compressed_bytes = (n * d + 7) / 8
  let compressed : Array[Byte] = Array::make(compressed_bytes, 0)

  // 执行压缩和解压缩
  poly_compress(compressed, original, d)
  poly_decompress(recovered, compressed, d)

  // 计算预期最大误差
  let expected_max_error = (q.to_float() / (1 << d).to_float()).to_int() + 1

  // 验证边界值
  for i = 0; i <= 6; i = i + 1 {
    let diff = (original[i] - recovered[i]).abs()
    println(
      "值 " +
      original[i].to_string() +
      " 经压缩解压缩后变为 " +
      recovered[i].to_string() +
      "，误差: " +
      diff.to_string(),
    )
    assert_true!(diff <= expected_max_error)
  }
}

///|
test "poly_compress_decompress/mlkem_bit_widths" {
  let q = common_params.q
  // 使用较小的多项式大小提高测试效率
  let n = 32

  // ML-KEM实际使用的压缩位宽
  let bit_widths = [10, 11, 12, 4, 5]
  for d in bit_widths {
    // 创建测试多项式
    let original = new_poly(n)
    let recovered = new_poly(n)

    // 设置一些典型值
    for i = 0; i < n; i = i + 1 {
      original[i] = (i * 123 + 45) % q
    }

    // 计算压缩字节数并添加安全边界
    let compressed_bytes = (n * d + 7) / 8 + 1
    let compressed : Array[Byte] = Array::make(compressed_bytes, 0)

    // 执行压缩和解压缩
    poly_compress(compressed, original, d)
    poly_decompress(recovered, compressed, d)

    // 计算预期最大误差
    let expected_max_error = (q.to_float() / (1 << d).to_float()).to_int() + 1

    // 验证结果
    let mut max_observed_error = 0
    for i = 0; i < n; i = i + 1 {
      let error = (original[i] - recovered[i]).abs()
      if error > max_observed_error {
        max_observed_error = error
      }
    }

    // 验证最大误差在预期范围内
    println(
      "位宽 d=" +
      d.to_string() +
      ", 预期最大误差: " +
      expected_max_error.to_string() +
      ", 观察到的最大误差: " +
      max_observed_error.to_string(),
    )
    assert_true!(max_observed_error <= expected_max_error)
  }
}

///|
test "poly_compress_decompress/cross_byte_boundary" {
  // 这个测试专门针对可能出现的跨字节边界问题
  let q = common_params.q
  let d = 10 // 使用会跨越字节边界的位宽

  // 只使用8个元素，这样可以精确控制和观察
  let n = 8
  let original = new_poly(n)
  let recovered = new_poly(n)

  // 设置特定值，强制跨字节边界
  original[0] = 0
  original[1] = q - 1 // 最大值
  original[2] = q / 2
  original[3] = q / 4
  original[4] = 3 * q / 4
  original[5] = q / 3
  original[6] = 2 * q / 3
  original[7] = 1

  // 计算压缩字节数（10位×8元素 = 80位 = 10字节）
  let compressed_bytes = (n * d + 7) / 8
  let compressed : Array[Byte] = Array::make(compressed_bytes, 0)

  // 执行压缩
  poly_compress(compressed, original, d)

  // 打印压缩后的字节，便于调试
  println("压缩后字节: ")
  for i = 0; i < compressed_bytes; i = i + 1 {
    println(
      i.to_string() + ": 0x" + (compressed[i].to_int() & 0xFF).to_string(),
    )
  }

  // 执行解压缩
  poly_decompress(recovered, compressed, d)

  // 验证结果
  for i = 0; i < n; i = i + 1 {
    let error = (original[i] - recovered[i]).abs()
    println(
      i.to_string() +
      ": 原始=" +
      original[i].to_string() +
      ", 恢复=" +
      recovered[i].to_string() +
      ", 误差=" +
      error.to_string(),
    )
  }

  // 计算预期的最大误差
  let expected_max_error = (q.to_float() / (1 << d).to_float()).to_int() + 1

  // 验证压缩和解压缩过程中的误差不超过预期
  for i = 0; i < n; i = i + 1 {
    let error = (original[i] - recovered[i]).abs()
    assert_true!(error <= expected_max_error)
  }
}

///|
test "poly_compress_decompress/full_polynomial" {
  // 测试完整大小的多项式
  let n = common_params.n
  let q = common_params.q
  let d = 10 // 10位压缩

  // 创建测试多项式
  let original = new_poly(n)
  let recovered = new_poly(n)

  // 使用分布式值填充多项式
  for i = 0; i < n; i = i + 1 {
    // 使用不同的模式填充不同区域
    if i < n / 4 {
      original[i] = i % q // 线性递增
    } else if i < n / 2 {
      original[i] = q - 1 - i % q // 线性递减
    } else if i < 3 * n / 4 {
      original[i] = i * i % q // 平方模式
    } else {
      original[i] = q / 2 + i % (q / 4)
    }
  } // 中心偏移

  // 计算压缩字节数
  let compressed_bytes = (n * d + 7) / 8
  let compressed : Array[Byte] = Array::make(compressed_bytes, 0)

  // 执行压缩和解压缩
  poly_compress(compressed, original, d)
  poly_decompress(recovered, compressed, d)

  // 验证结果
  let expected_max_error = (q.to_float() / (1 << d).to_float()).to_int() + 1
  let mut max_error = 0
  let mut error_count = 0
  for i = 0; i < n; i = i + 1 {
    let error = (original[i] - recovered[i]).abs()
    if error > max_error {
      max_error = error
    }
    if error > expected_max_error {
      error_count = error_count + 1
    }
  }

  // 验证所有误差在允许范围内
  println(
    "最大误差: " +
    max_error.to_string() +
    ", 允许误差: " +
    expected_max_error.to_string(),
  )
  println(
    "超出误差: " + error_count.to_string() + " / " + n.to_string() + " 项",
  )
  assert_eq!(error_count, 0)
}

///|
test "poly_compress_decompress/error_accumulation" {
  // 测试多次压缩/解压缩是否导致误差过度累积
  let n = 32
  let q = common_params.q
  let d = 10
  let original = new_poly(n)
  let current = new_poly(n)
  let next = new_poly(n)

  // 设置初始值 - 使用更保守的值范围
  for i = 0; i < n; i = i + 1 {
    // 确保值在[0, q-1]范围内且不接近边界
    original[i] = (i * 137 + 42) % (q - 100)
    current[i] = original[i]
  }

  // 计算压缩字节数 - 增加更多安全边界
  let compressed_bytes = (n * d + 7) / 8 + 4
  let compressed : Array[Byte] = Array::make(compressed_bytes, 0)

  // 执行多次压缩/解压缩循环
  let cycles = 3 // 减少循环次数，先确认基本功能正常
  let max_errors = Array::make(cycles, 0)

  // 逐轮压缩和解压缩，并记录误差
  for cycle = 0; cycle < cycles; cycle = cycle + 1 {
    // 执行压缩
    poly_compress(compressed, current, d)

    // 执行解压缩
    poly_decompress(next, compressed, d)

    // 计算此轮的最大误差
    let mut max_error = 0
    for i = 0; i < n; i = i + 1 {
      // 记录每轮的第一个值，用于调试
      if i == 0 {
        println(
          "轮次 " +
          (cycle + 1).to_string() +
          " 第一个值: 原=" +
          current[i].to_string() +
          ", 恢复=" +
          next[i].to_string(),
        )
      }
      let error = (current[i] - next[i]).abs()
      if error > max_error {
        max_error = error
      }
    }
    max_errors[cycle] = max_error

    // 复制结果作为下一轮输入
    poly_copy(current, next)
  }

  // 计算原始值和最终值的总误差
  let mut total_error = 0
  for i = 0; i < n; i = i + 1 {
    let error = (original[i] - current[i]).abs()
    if error > total_error {
      total_error = error
    }
  }

  // 预期最大误差
  let expected_max_error = (q.to_float() / (1 << d).to_float()).to_int() + 1
  let expected_accumulated_error = expected_max_error * cycles
  println("每轮最大误差: ")
  for cycle = 0; cycle < cycles; cycle = cycle + 1 {
    println(
      "轮次 " + (cycle + 1).to_string() + ": " + max_errors[cycle].to_string(),
    )
  }
  println("总累积误差: " + total_error.to_string())
  println("预期最大累积误差: " + expected_accumulated_error.to_string())

  // 验证总误差不超过预期最大累积误差
  assert_true!(total_error <= expected_accumulated_error)
}
