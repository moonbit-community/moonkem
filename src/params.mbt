// ML-KEM (CRYSTALS-Kyber) 协议的参数定义
// 依据 NIST FIPS 203 标准

///|
/// ML-KEM 算法所有安全级别共享的通用参数
pub struct CommonParams {
  /// 多项式阶数 (n = 256)
  n : Int
  /// 模数 (q = 3329)
  q : Int
  /// 哈希函数输出长度(字节)
  hash_bytes : Int
  /// 共享密钥长度(字节)
  ss_bytes : Int
  /// 对称密钥长度(字节)
  sym_bytes : Int
}

///|
/// ML-KEM 特定安全级别的参数
pub struct SecurityParams {
  /// 安全级别名称
  name : String
  /// 安全强度(位)
  security_bits : Int
  /// 矩阵/向量维度 (k)
  k : Int
  /// 噪声分布参数 (η, eta)
  eta : Int
  /// 公钥压缩参数 (du)
  du : Int
  /// 密文压缩参数 (dv)
  dv : Int
  /// 种子字节长度
  seed_bytes : Int
  /// 公钥字节长度
  public_key_bytes : Int
  /// 私钥字节长度
  secret_key_bytes : Int
  /// 密文字节长度
  ciphertext_bytes : Int
}

///|
/// ML-KEM 共享参数
pub let common_params : CommonParams = {
  n: 256,
  q: 3329,
  hash_bytes: 32,
  ss_bytes: 32,
  sym_bytes: 32,
}

///|
/// ML-KEM-512 参数 (NIST 安全等级 1)
pub let ml_kem_512 : SecurityParams = {
  name: "ML-KEM-512",
  security_bits: 128,
  k: 2,
  eta: 3,
  du: 10,
  dv: 4,
  seed_bytes: 32,
  public_key_bytes: 800, // k*n*(12/8) + 32
  secret_key_bytes: 1632, // 12*n/8 + 32 + 32 + 800
  ciphertext_bytes: 768, // k*n*(10/8) + n*(4/8)
}

///|
/// ML-KEM-768 参数 (NIST 安全等级 3)
pub let ml_kem_768 : SecurityParams = {
  name: "ML-KEM-768",
  security_bits: 192,
  k: 3,
  eta: 2,
  du: 10,
  dv: 4,
  seed_bytes: 32,
  public_key_bytes: 1184, // k*n*(12/8) + 32
  secret_key_bytes: 2400, // 12*n/8 + 32 + 32 + 1184
  ciphertext_bytes: 1088, // k*n*(10/8) + n*(4/8)
}

///|
/// ML-KEM-1024 参数 (NIST 安全等级 5)
pub let ml_kem_1024 : SecurityParams = {
  name: "ML-KEM-1024",
  security_bits: 256,
  k: 4,
  eta: 2,
  du: 11,
  dv: 5,
  seed_bytes: 32,
  public_key_bytes: 1568, // k*n*(12/8) + 32
  secret_key_bytes: 3168, // 12*n/8 + 32 + 32 + 1568
  ciphertext_bytes: 1568, // k*n*(11/8) + n*(5/8)
}

///|
/// 返回指定安全级别的参数
/// @param level 安全级别 (512, 768 或 1024)
/// @return 对应安全级别的参数
pub fn get_params(level : Int) -> SecurityParams {
  if level == 512 {
    return ml_kem_512
  } else if level == 768 {
    return ml_kem_768
  } else if level == 1024 {
    return ml_kem_1024
  } else {
    abort("Invalid security level. Valid options: 512, 768, 1024")
  }
}

///|
/// ML-KEM中NTT相关的常数参数
pub struct NTTParams {
  /// 原根 ζ (zeta)
  zeta : Int
  /// 二元多项式乘法的蒙哥马利参数
  montgomery_r : Int
  /// 蒙哥马利约简所需的参数
  montgomery_r2 : Int
  /// 模逆运算的常数: -q^(-1) mod 2^16
  q_inv : Int
  /// 模数分解: q = 2^d - epsilon, d=13
  d : Int
  epsilon : Int
}

///|
/// ML-KEM中使用的NTT参数(用于模数q = 3329)
pub let ntt_params : NTTParams = {
  zeta: 17,
  montgomery_r: 1,
  montgomery_r2: 1,
  q_inv: 3327,
  d: 13,
  epsilon: 3329 - (1 << 13), // 3329 - 8192 = -4863
}

///|
/// 用于Barrett约简的参数常量
pub let barrett_reduce_factor : Int = (1 << 26) / common_params.q
