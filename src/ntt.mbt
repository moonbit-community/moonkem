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
pub const QINV : Int = 62209

///| Montgomery form constant R^2 = 2^32 mod q
pub const R2 : Int = 1353

///|
typealias Array[Int] as Function

///|
/// Precomputed twiddle factors for NTT
/// In ML-KEM, these are powers of ζ^br(i), where br(i) is the bit-reversal of i
let zetas : Array[Int] = [
  1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569,
  1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393,
  2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513,
  632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647,
  2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100,
  1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952,
  1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220,
  375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092,
  403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
]

///| 从种子生成 NTT 域采样多项式（常用于格密码）
///
/// Parameters
///
/// - `seed` : 用于采样的字节数组（ByteArray），作为熵源输入
///
/// Returns
///
/// - `Array[Int]` : 长度为 256 的整型数组 `a_hat`，表示 NTT 域多项式系数，每个系数 < `PARAM_Q`
///
/// Errors
///
/// - 无显式错误抛出，但需保证 `seed` 足够随机，`PARAM_Q` 已定义且合理
///
/// Description
///
/// 本函数通过“可扩展输出函数”（XOF，通常为 SHAKE 等）
/// 从给定种子 deterministically 采样长度为 256 的多项式系数，每个系数为 `[0, PARAM_Q)` 区间整数：
///
/// 1. 初始化 XOF 吸收上下文，并吸收种子
/// 2. 不断挤出 3 字节块，将每 3 字节解码为两个候选系数（d1、d2）
/// 3. 满足 `< PARAM_Q` 则填入输出数组，否则丢弃
/// 4. 返回填充满的 NTT 域多项式系数
///
/// 常用于格基公钥加密、数字签名等原语的安全参数初始化
///
/// Example
/// ```
/// let poly = sample_ntt(seed)
/// ```
pub fn sample_ntt(seed : ByteArray) -> Function {
  let mut ctx = xof_init()
  ctx = xof_absorb(ctx, seed)
  let a_hat = Array::make(256, 0)
  let mut j = 0
  while j < 256 {
    let (_ctx, c) = xof_squeeze(ctx, 3)
    let d1 = c[0].to_int() + 256 * (c[1].to_int() & 0x0F)
    let d2 = (c[1] >> 4).to_int() + 16 * c[2].to_int()
    if d1 < PARAM_Q {
      a_hat[j] = d1
      j += 1
    }
    if j < 256 && d2 < PARAM_Q {
      a_hat[j] = d2
      j += 1
    }
  }
  a_hat
}

///| 从种子生成 NTT 域采样多项式
///
/// Parameters
///
/// - `seed` : 用于采样的字节数组（ByteArray），作为熵源输入
///
/// Returns
///
/// - `Array[Int]` : 长度为 256 的整型数组 `a_hat`，表示 NTT 域多项式系数，每个系数 < `PARAM_Q`
///
/// Errors
///
/// - 无显式错误抛出，但需保证 `seed` 足够随机，`PARAM_Q` 已定义且合理
///
/// Description
///
/// 本函数通过“可扩展输出函数”（XOF，通常为 SHAKE 等）
/// 从给定种子 deterministically 采样长度为 256 的多项式系数，每个系数为 `[0, PARAM_Q)` 区间整数：
///
/// 1. 初始化 XOF 吸收上下文，并吸收种子
/// 2. 不断挤出 3 字节块，将每 3 字节解码为两个候选系数（d1、d2）
/// 3. 满足 `< PARAM_Q` 则填入输出数组，否则丢弃
/// 4. 返回填充满的 NTT 域多项式系数
///
/// 常用于格基公钥加密、数字签名等原语的安全参数初始化
///
/// Example
/// ```
/// let poly = sample_ntt(seed)
/// ```
pub fn sample_poly_cbd(seed : ByteArray) -> Function {
  let b = bytes_to_bits(seed)
  let f = Array::make(PARAM_N, 0)
  for i = 0; i < PARAM_N; i = i + 1 {
    let mut x = 0
    let mut y = 0
    let base = 2 * i * PARAM_ETA1
    for j = 0; j < PARAM_ETA1; j = j + 1 {
      x = x + b[base + j]
      y = y + b[base + PARAM_ETA1 + j]
    }
    f[i] = mod_q(x - y, PARAM_Q)
  }
  f
}

///|
/// Computes the Number Theoretic Transform (NTT) of a polynomial. The NTT is a
/// specialized version of the Discrete Fourier Transform (DFT) operating in a
/// finite field, used in ML-KEM for efficient polynomial multiplication.
///
/// Parameters:
///
/// * `polynomial` : A polynomial represented as an array of integers
/// (coefficients), where each coefficient is in the range \[0, q-1] with q =
/// 3329. The length of the array must be exactly 256.
///
/// Returns a new array representing the polynomial in NTT domain.
///
/// Throws an error if the input array's length is not exactly 256.
///
/// Example:
///
/// ```moonbit
/// ///|
/// test "ntt/basic" {
///   let f = Array::make(256, 0)
///   f[0] = 1
///   f[1] = 2
///   let hat_f = ntt(f)
///   inspect!(hat_f[0], content="3")
///   inspect!(hat_f[1], content="2078")
/// }
/// ```
pub fn ntt(f : Function) -> Function {
  if f.length() != PARAM_N {
    abort("Input array must have length exactly PARAM_N")
  }
  let hat_f : Function = f.copy()
  let mut i = 1
  for len = 128; len >= 2; len = len >> 1 {
    for start = 0; start < 256; start = start + 2 * len {
      let zeta = mod_q(zetas[i], PARAM_Q)
      i += 1
      for j = start; j < start + len; j = j + 1 {
        let t = mod_q(zeta * hat_f[j + len], PARAM_Q)
        hat_f[j + len] = mod_q(hat_f[j] - t, PARAM_Q)
        hat_f[j] = mod_q(hat_f[j] + t, PARAM_Q)
      }
    }
  }
  hat_f
}

///|
/// Computes the inverse Number Theoretic Transform (INTT) of a polynomial. The
/// INTT converts a polynomial from NTT domain back to the normal domain, which
/// is essential for polynomial arithmetic in ML-KEM (CRYSTALS-Kyber).
///
/// Parameters:
///
/// * `polynomial` : A polynomial in NTT domain represented as an array of
/// integers (coefficients), where each coefficient is in the range \[0, q-1]
/// with q = 3329. The length of the array must be exactly 256.
///
/// Returns a new array representing the polynomial in normal domain.
///
/// Throws an error if the input array's length is not exactly 256.
///
/// Example:
///
/// ```moonbit
/// ///|
/// test "intt/basic" {
///   let f = Array::make(256, 0)
///   f[0] = 3
///   f[1] = 2078
///   let orig_f = intt(f)
///   inspect!(orig_f[0], content="1")
///   inspect!(orig_f[1], content="2")
/// }
/// ```
pub fn intt(hat_f : Function) -> Function {
  if hat_f.length() != PARAM_N {
    abort("Input array must have length exactly PARAM_N")
  }
  let f = hat_f.copy()
  let mut i = 127
  for len = 2; len <= 128; len = len << 1 {
    for start = 0; start < 256; start = start + 2 * len {
      let zeta = mod_q(zetas[i], PARAM_Q)
      i -= 1
      for j = start; j < start + len; j = j + 1 {
        let t = f[j]
        f[j] = mod_q(t + f[j + len], PARAM_Q)
        f[j + len] = mod_q(zeta * mod_q(f[j + len] - t, PARAM_Q), PARAM_Q)
      }
    }
  }
  poly_scalar_mul(f, f, 3303)
  f
}

///|
test {
  let f = Array::make(PARAM_N, 0)
  for i = 0; i < PARAM_N; i = i + 1 {
    f[i] = i
  }
  let hat_f = ntt(f)
  let f2 = intt(hat_f)
  assert_eq(f, f2)
}

///|
pub fn multiply_ntts(f_hat : Function, g_hat : Function) -> Function {
  let h_hat : Function = Array::make(256, 0)
  for i = 0; i < 128; i = i + 1 {
    let (a, b) = base_case_multiply(
      f_hat[2 * i],
      f_hat[2 * i + 1],
      g_hat[2 * i],
      g_hat[2 * i + 1],
      zetas[i],
    )
    h_hat[2 * i] = a
    h_hat[2 * i + 1] = b
  }
  h_hat
}

///|
pub fn base_case_multiply(
  a0 : Int,
  a1 : Int,
  b0 : Int,
  b1 : Int,
  gamma : Int
) -> (Int, Int) {
  (a0 * b0 + a1 * b1 * gamma, a0 * b1 + a1 * b0)
}

///|
pub fn ntt_pointwise_mul(a : Array[Int], b : Array[Int], q : Int) -> Array[Int] {
  let n = a.length()
  let out = Array::make(n, 0)
  for i = 0; i < n; i = i + 1 {
    out[i] = a[i] * b[i] % q
    if out[i] < 0 {
      out[i] = out[i] + q
    }
  }
  out
}
