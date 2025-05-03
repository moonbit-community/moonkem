// ML-KEM (CRYSTALS-Kyber) 数据类型定义

///|
/// 多项式类型，基本构建块
/// 表示R_q = Z_q[X]/(X^n + 1)中的元素
/// 其中q = 3329, n = 256
typealias Poly = Array[Int]

///|
/// 多项式向量类型
/// k维多项式向量，k取决于安全级别(k=2,3,4)
typealias PolyVec = Array[Poly]

///|
/// 公钥结构体
/// 包含公钥多项式向量t和用于生成矩阵A的种子rho
pub struct PublicKey {
  /// 公钥多项式向量 t = A·s + e
  t : PolyVec

  /// 用于确定性生成矩阵A的种子
  rho : ByteArray
}

///|
/// 私钥结构体
/// 包含私钥多项式向量s和额外信息
pub struct SecretKey {
  /// 私钥多项式向量s
  s : PolyVec

  /// 公钥值t (= A·s + e)
  t : PolyVec

  /// 用于确定性生成矩阵A的种子
  rho : ByteArray

  /// 公钥的哈希值，用于侧信道防护
  h : ByteArray
  /// 随机字节，用于确定性re-encryption
  z : ByteArray
}

///|
/// 密文结构体
/// 包含加密输出的两个部分
pub struct Ciphertext {
  /// 密文第一部分，u = A^T·r + e1
  u : PolyVec

  /// 密文第二部分，v = t^T·r + e2 + ⌈q/2⌉·m
  v : Poly
}

///|
/// 创建指定长度的新多项式(全部填充0)
/// @param n 多项式阶数，通常为256
/// @return 新的空多项式
pub fn new_poly(n : Int) -> Poly {
  return Array::make(n, 0)
}

///|
/// 创建指定维度的多项式向量(全部填充0)
/// @param k 向量维度，与安全级别相关(k=2,3,4)
/// @param n 多项式阶数，通常为256
/// @return 新的空多项式向量
pub fn new_poly_vec(k : Int, n : Int) -> PolyVec {
  let vec = Array::make(k, Array::make(0, 0))
  for i = 0; i < k; i = i + 1 {
    vec[i] = new_poly(n)
  }
  return vec
}

///|
/// 基于安全参数创建新的公钥结构体
/// @param params ML-KEM安全参数
/// @return 初始化的公钥
pub fn new_public_key(params : SecurityParams) -> PublicKey {
  let t = new_poly_vec(params.k, common_params.n)
  let rho : Array[Byte] = ByteArray::make(params.seed_bytes, 0)
  return { t, rho }
}

///|
/// 基于安全参数创建新的私钥结构体
/// @param params ML-KEM安全参数
/// @return 初始化的私钥
pub fn new_secret_key(params : SecurityParams) -> SecretKey {
  let n = common_params.n
  let s = new_poly_vec(params.k, n)
  let t = new_poly_vec(params.k, n)
  let rho : Array[Byte] = ByteArray::make(params.seed_bytes, 0)
  let h : Array[Byte] = ByteArray::make(common_params.hash_bytes, 0)
  let z : Array[Byte] = ByteArray::make(common_params.sym_bytes, 0)
  return { s, t, rho, h, z }
}

///|
/// 基于安全参数创建新的密文结构体
/// @param params ML-KEM安全参数
/// @return 初始化的密文
pub fn new_ciphertext(params : SecurityParams) -> Ciphertext {
  let n = common_params.n
  let u = new_poly_vec(params.k, n)
  let v = new_poly(n)
  return { u, v }
}
