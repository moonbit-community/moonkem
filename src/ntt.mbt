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
typealias Function = Array[Int]

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
  assert_eq!(f, f2)
}
