///|
typealias Array[Byte] as ByteArray

///| 基于格密码 KEM 的密钥对生成函数（Key Generation for Lattice-based KEM）
///
/// Parameters
///
/// - `d` : 字节数组（ByteArray），作为主熵源（含身份信息/随机源）
///
/// Returns
///
/// - `(ByteArray, ByteArray)` : 返回密钥对 (公钥, 私钥)
///   - `ek_PKE` ：编码后的公钥字节数组（包括 t_hat、多项式种子 rho）
///   - `dk_PKE` ：编码后的私钥字节数组（包括 s_hat）
///
/// Errors
///
/// - 无显式错误抛出，但要求：
///   - `@kem.g`、`@kem.prf`、`@kem.sample_ntt`、`@kem.sample_poly_cbd`、`@kem.ntt`、`@kem.ntt_pointwise_mul`、`@kem.poly_add`、`@kem.poly_copy` 等依赖的 KEM 相关函数已正确实现
///   - `PARAM_Q` 已正确定义
///
/// Description
///
/// 此函数实现格基密钥封装机制（KEM）中的密钥对生成步骤：
///
/// 1. **派生种子**：
///    - 对输入 `d` 加标识后送入 KEM 派生，获得 `rho`（公钥多项式种子）、`sigma`（私钥熵源）
///
/// 2. **生成公钥矩阵**：
///    - 以 rho、i、j 为种子采样，生成 NTT 域 4x4 多项式矩阵 `a_hat`
///
/// 3. **生成私钥向量**：
///    - 用 sigma 和计数器 n 通过伪随机函数 `prf` 采样，CBD 采样多项式，得 4 维私钥向量 s
///    - 同理再采样误差多项式向量 e
///    - 分别对 s、e 做 NTT 变换，得 s_hat, e_hat
///
/// 4. **公钥计算**：
///    - 计算 t_hat[i] = sum_j a_hat[i][j] * s_hat[j] + e_hat[i]
///    - 并编码 t_hat，拼接 rho 构成公钥 ek_PKE
///
/// 5. **私钥计算**：
///    - 仅编码 s_hat，作为私钥 dk_PKE
///
/// 最终返回（公钥，私钥）二元组，供后续加解密或密钥封装使用。
///
/// Example
/// ```
/// let (ek, dk) = keygen(d)
/// ```
pub fn keygen(d : ByteArray) -> (ByteArray, ByteArray) {
  d.push(4)
  let (rho, sigma) = @kem.g(d)
  let mut n = 0
  let a_hat = Array::make(4, Array::make(4, Array::make(256, 0)))
  for i = 0; i < 4; i = i + 1 {
    for j = 0; j < 4; j = j + 1 {
      let seed_a = rho.copy()
      seed_a.push(j.to_byte())
      seed_a.push(i.to_byte())
      a_hat[i][j] = @kem.sample_ntt(seed_a)
    }
  }
  let s = Array::make(4, Array::make(256, 0))
  for i = 0; i < 4; i = i + 1 {
    let buf = @kem.prf(2, sigma, n.to_byte())
    s[i] = @kem.sample_poly_cbd(buf)
    n = n + 1
  }
  let e = Array::make(4, Array::make(256, 0))
  for i = 0; i < 4; i = i + 1 {
    let buf = @kem.prf(2, sigma, n.to_byte())
    e[i] = @kem.sample_poly_cbd(buf)
  }
  let s_hat = []
  for item in s {
    s_hat.push(@kem.ntt(item))
  }
  let e_hat = []
  for item in e {
    e_hat.push(@kem.ntt(item))
  }
  let t_hat = Array::make(4, Array::make(256, 0))
  for i = 0; i < 4; i = i + 1 {
    let acc = Array::make(256, 0)
    for j = 0; j < 4; j = j + 1 {
      let prod = @kem.ntt_pointwise_mul(a_hat[i][j], s_hat[j], @kem.PARAM_Q)
      if j == 0 {
        @kem.poly_copy(acc, prod)
      } else {
        @kem.poly_add(acc, acc, prod)
      }
    }
    @kem.poly_add(acc, acc, e_hat[i])
    @kem.poly_copy(t_hat[i], acc)
  }
  let ek_PKE = byte_encode12(t_hat)
  ek_PKE.append(rho)
  let dk_PKE = byte_encode12(s_hat)
  (ek_PKE, dk_PKE)
}

///|
fn byte_encode12(polys : Array[Array[Int]]) -> ByteArray {
  let out = []
  for poly in polys {
    let buf : Array[Byte] = Array::make(256 * 12 / 8, 0)
    @kem.poly_compress(buf, poly, 12)
    out.append(buf)
  }
  out
}
