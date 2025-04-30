///|
/// The NTT (Number Theoretic Transform) module implements algorithms for efficient polynomial
/// multiplication required by ML-KEM (CRYSTALS-Kyber).
/// This module is based on the ML-KEM (CRYSTALS-Kyber) specification.

// 基本参数定义
///| ML-KEM 模数
pub const PARAM_Q : Int = 3329 // KYBER_Q

///| ML-KEM 多项式度数
pub const PARAM_N : Int = 256 // KYBER_N

///| ML-KEM 安全级别参数 (2=Kyber512, 3=Kyber768, 4=Kyber1024)
pub const PARAM_K : Int = 4 // KYBER_K

///| 噪声分布参数
pub const PARAM_ETA1 : Int = 2 // KYBER_ETA1 (K=4时为2)

///|
pub const PARAM_ETA2 : Int = 2 // KYBER_ETA2

// Montgomery 相关常量
///| Montgomery 规约常量 -q^(-1) mod 2^16
pub const QINV : Int = 3327

///| Montgomery form constant R^2 = 2^32 mod q
pub const R2 : Int = 1353

///|
/// Precomputed twiddle factors for NTT
/// In ML-KEM, these are powers of ζ^br(i), where br(i) is the bit-reversal of i
let zetas : Array[Int] = [
  2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127,
  1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608,
  1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047, 1785, 516, 3321,
  3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830, 107, 1908, 3082, 2378,
  2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226, 430, 555, 843, 2078, 871, 1550,
  105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182, 2552,
  1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610,
  1322, 2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799,
  2051, 794, 1819, 2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
]

///|
/// Precomputed inverse twiddle factors for INTT
let zetas_inv : Array[Int] = [
  1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535, 1278,
  1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465, 1285, 2007,
  2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685, 1590, 2210, 602,
  1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235, 3152, 2742, 2907, 3224,
  1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652, 1065, 2881, 725, 1508, 2368,
  398, 951, 247, 1421, 3222, 2499, 271, 90, 853, 1860, 3203, 1162, 1618, 666, 320,
  8, 2813, 1544, 282, 1838, 1293, 2314, 552, 2677, 2106, 1571, 205, 2918, 1542, 2721,
  2597, 2312, 681, 130, 1602, 1871, 829, 2946, 3065, 1325, 2756, 1861, 1474, 1202,
  2367, 3147, 1752, 2707, 171, 3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
]

///|
/// Performs Montgomery reduction-based modular multiplication
/// Montgomery multiplication: (a * b * R^(-1)) mod q, where R = 2^16
pub fn mont_mul(a : Int, b : Int) -> Int {
  let t = (a * b) & 0xFFFF // Low 16 bits
  let u = (t * QINV) & 0xFFFF // t * QINV mod 2^16
  let v = t + u * PARAM_Q // t + u * q
  let r = v >> 16 // v / 2^16
  if r >= PARAM_Q {
    return r - PARAM_Q
  } else {
    return r
  }
}

///|
/// Converts an integer to Montgomery form: a -> a*R mod q
pub fn to_mont(a : Int) -> Int {
  return mont_mul(a, R2)
}

///|
/// Initializes polynomial coefficients, converting them to NTT-friendly Montgomery form
pub fn poly_to_mont(poly : Array[Int]) -> Unit {
  for i in 0..<PARAM_N {
    poly[i] = to_mont(poly[i])
  }
}

///|
/// Performs forward NTT transform
/// Input: polynomial coefficients, Output: NTT representation (bitreversed order)
pub fn ntt(poly : Array[Int]) -> Unit {
  if poly.length() != PARAM_N {
    abort("Input array must have length exactly PARAM_N")
  }

  // 按照 Kyber 参考实现的 NTT 算法精确实现
  let mut k = 1
  let mut len = 128
  while len >= 2 {
    let mut start = 0
    while start < PARAM_N {
      let zeta = zetas[k]
      k += 1
      let mut j = start
      while j < start + len {
        let t = mont_mul(zeta, poly[j + len])
        poly[j + len] = poly[j] - t
        if poly[j + len] < 0 {
          poly[j + len] += PARAM_Q
        }
        poly[j] = poly[j] + t
        if poly[j] >= PARAM_Q {
          poly[j] -= PARAM_Q
        }
        j += 1
      }
      start = start + 2 * len
    }
    len = len >> 1
  }
}

///|
/// Performs inverse NTT transform and conversion from Montgomery form
/// Input: polynomial in NTT representation (bitreversed), Output: standard coefficient representation
pub fn intt(poly : Array[Int]) -> Unit {
  if poly.length() != PARAM_N {
    abort("Input array must have length exactly PARAM_N")
  }

  // 按照 Kyber 参考实现精确实现的 INTT 算法
  let mut k = 0
  let mut len = 2
  while len <= 128 {
    let mut start = 0
    while start < PARAM_N {
      let zeta = zetas_inv[k] // 添加这行来定义 zeta
      k += 1 // 递增 k
      let mut j = start
      while j < start + len {
        let t = poly[j]
        poly[j] = barrett_reduce(t + poly[j + len])
        poly[j + len] = t - poly[j + len]
        poly[j + len] = mont_mul(zeta, poly[j + len])
        j += 1
      }
      start = start + 2 * len
    }
    len = len << 1
  }
  // 标准化因子 (n^-1 mod q)
  let n_inv = zetas_inv[127] // zetas_inv[127]

  // 将结果乘以 n^-1 并转换回标准形式
  for j in 0..<PARAM_N {
    poly[j] = mont_mul(poly[j], n_inv)
  }
}

///|
/// Barrett reduction for modular arithmetic
/// Used in INTT implementation to match reference code
pub fn barrett_reduce(a : Int) -> Int {
  let v = (a.to_float() * 20159.0 / 67108864.0).to_int() // v = ((a<<26)/q+0.5)>>26
  let t = v * PARAM_Q
  let r = a - t
  if r >= PARAM_Q {
    return r - PARAM_Q
  }
  if r < 0 {
    return r + PARAM_Q
  }
  return r
}

///|
/// Pointwise multiplication of polynomials in the NTT domain
/// Computes c = a * b mod (X^n + 1)
pub fn poly_mul(c : Array[Int], a : Array[Int], b : Array[Int]) -> Unit {
  if a.length() != PARAM_N || b.length() != PARAM_N || c.length() != PARAM_N {
    abort("Input and output arrays must have length PARAM_N")
  }

  // 按点乘法 (pointwise multiplication)
  for i in 0..<PARAM_N {
    c[i] = mont_mul(a[i], b[i])
  }
}

///|
/// Multiplies two polynomials in coefficient representation
/// Inputs: two polynomials, Output: their product (in coefficient representation)
pub fn polynomial_multiply(
  c : Array[Int],
  a : Array[Int],
  b : Array[Int]
) -> Unit {
  if a.length() != PARAM_N || b.length() != PARAM_N || c.length() != PARAM_N {
    abort("Input arrays must have length PARAM_N")
  }

  // 创建临时副本避免修改输入
  let a_copy = a.copy()
  let b_copy = b.copy()

  // 转换到Montgomery形式
  poly_to_mont(a_copy)
  poly_to_mont(b_copy)

  // 执行NTT变换
  ntt(a_copy)
  ntt(b_copy)

  // 按点乘法
  poly_mul(c, a_copy, b_copy)

  // 逆变换回系数表示
  intt(c)
}

///|
/// 计算整数的幂（x^n）
pub fn pow(x : Int, n : Int) -> Int {
  if n == 0 {
    return 1
  }
  if n == 1 {
    return x
  }
  let half = pow(x, n / 2)
  if n % 2 == 0 {
    return half * half
  } else {
    return half * half * x
  }
}

///|
/// 计算浮点数的幂（x^n）
pub fn pow_float(x : Float, n : Int) -> Float {
  if n == 0 {
    return 1.0
  }
  if n == 1 {
    return x
  }
  let half = pow_float(x, n / 2)
  if n % 2 == 0 {
    return half * half
  } else {
    return half * half * x
  }
}
