// ML-KEM (CRYSTALS-Kyber) 多项式操作实现

///|
/// 模运算，确保结果在[0, q-1]范围内
/// @param a 输入整数
/// @param q 模数
/// @return 模运算结果
pub fn mod_q(a : Int, q : Int) -> Int {
  let r = a % q
  if r < 0 {
    return r + q
  }
  r
}

///|
/// 多项式加法: c = a + b mod q
/// @param c 结果多项式 (可以与a或b相同)
/// @param a 第一个多项式
/// @param b 第二个多项式
pub fn poly_add(c : Poly, a : Poly, b : Poly) -> Unit {
  let n = common_params.n
  let q = common_params.q
  for i = 0; i < n; i = i + 1 {
    c[i] = mod_q(a[i] + b[i], q)
  }
}

///|
/// 多项式减法: c = a - b mod q
/// @param c 结果多项式 (可以与a或b相同)
/// @param a 第一个多项式
/// @param b 第二个多项式
pub fn poly_sub(c : Poly, a : Poly, b : Poly) -> Unit {
  let n = common_params.n
  let q = common_params.q
  for i = 0; i < n; i = i + 1 {
    c[i] = mod_q(a[i] - b[i], q)
  }
}

///|
/// 多项式乘以标量: b = a * scalar mod q
/// @param b 结果多项式 (可以与a相同)
/// @param a 输入多项式
/// @param scalar 标量
pub fn poly_scalar_mul(b : Poly, a : Poly, scalar : Int) -> Unit {
  let n = common_params.n
  let q = common_params.q
  for i = 0; i < n; i = i + 1 {
    b[i] = mod_q(a[i] * scalar, q)
  }
}

///|
/// 将多项式系数规约到中心表示 [-q/2, q/2)
/// @param a 需要规约的多项式
pub fn poly_reduce(a : Poly) -> Unit {
  let n = common_params.n
  let q = common_params.q
  let q_half = q / 2
  for i = 0; i < n; i = i + 1 {
    // 确保a[i]在[0, q-1]范围内
    let t = mod_q(a[i], q)

    // 转换到中心表示
    if t > q_half {
      a[i] = t - q
    } else {
      a[i] = t
    }
  }
}

///|
/// 多项式压缩: 将系数从[0,q-1]压缩到[0,2^d-1]
/// @param out 输出字节数组
/// @param poly 输入多项式
/// @param d 压缩位数
pub fn poly_compress(out : ByteArray, poly : Poly, d : Int) -> Unit {
  let n = poly.length()
  let q = common_params.q

  // 计算压缩因子
  let compress_factor = (1 << d).to_float() / q.to_float()

  // 临时存储压缩后的整数值
  let compressed = Array::make(n, 0)

  // 执行压缩映射
  for i = 0; i < n; i = i + 1 {
    let t = mod_q(poly[i], q)
    let scaled = (t.to_float() * compress_factor + 0.5).to_int()
    compressed[i] = if scaled >= (1 << d) { (1 << d) - 1 } else { scaled }
  }

  // 清空输出数组
  for i = 0; i < out.length(); i = i + 1 {
    out[i] = 0
  }

  // 改进后的位打包算法
  let mut bit_idx = 0
  for i = 0; i < n; i = i + 1 {
    let val = compressed[i]
    for j = 0; j < d; j = j + 1 {
      // 计算当前位应该写入的字节和位偏移
      let byte_idx = bit_idx / 8
      let bit_pos = bit_idx % 8

      // 确保不会越界
      if byte_idx < out.length() {
        // 设置对应的位
        if (val & (1 << j)) != 0 {
          out[byte_idx] = (out[byte_idx].to_int() | (1 << bit_pos)).to_byte()
        }
      }
      bit_idx = bit_idx + 1
    }
  }
}

///|
/// 多项式解压缩: 将系数从[0,2^d-1]解压缩回[0,q-1]
/// @param poly 输出多项式
/// @param in_bytes 输入字节数组
/// @param d 压缩位数
pub fn poly_decompress(poly : Poly, in_bytes : ByteArray, d : Int) -> Unit {
  let n = poly.length()
  let q = common_params.q

  // 计算解压缩因子
  let decompress_factor = q.to_float() / (1 << d).to_float()

  // 改进后的逐位读取算法
  let mut bit_idx = 0
  for i = 0; i < n; i = i + 1 {
    let mut val = 0
    for j = 0; j < d; j = j + 1 {
      // 计算当前位所在的字节和位偏移
      let byte_idx = bit_idx / 8
      let bit_pos = bit_idx % 8

      // 确保不会越界
      if byte_idx < in_bytes.length() {
        // 读取对应的位
        if (in_bytes[byte_idx].to_int() & (1 << bit_pos)) != 0 {
          val = val | (1 << j)
        }
      }
      bit_idx = bit_idx + 1
    }

    // 解压缩到原始范围
    poly[i] = (val.to_float() * decompress_factor + 0.5).to_int()
  }
}

///|
/// 检查多项式是否为零多项式
/// @param poly 待检查的多项式
/// @return 如果所有系数都是0则返回true
pub fn poly_is_zero(poly : Poly) -> Bool {
  let n = common_params.n
  for i = 0; i < n; i = i + 1 {
    if poly[i] != 0 {
      return false
    }
  }
  true
}

///|
/// 拷贝多项式: dst = src
/// @param dst 目标多项式
/// @param src 源多项式
pub fn poly_copy(dst : Poly, src : Poly) -> Unit {
  let n = src.length()
  for i = 0; i < n; i = i + 1 {
    dst[i] = src[i]
  }
}
