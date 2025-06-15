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
pub fn k_keygen(d : ByteArray) -> (ByteArray, ByteArray) {
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

///| 格密码 KEM 公钥加密函数（Encryption for Lattice-based KEM）  
///
/// Parameters
///
/// - `ek_PKE` : 公钥字节数组（ByteArray），由 keygen 生成
/// - `m` : 明文消息字节数组（ByteArray），需按协议压缩编码
/// - `r` : 加密用的随机字节数组（ByteArray），用作采样多项式熵源
///
/// Returns
///
/// - `ByteArray` : 密文（Ciphertext），包括编码后的 u 多项式和 v 多项式
///
/// Errors
///
/// - 无显式错误抛出，但依赖：
///   - 公钥编码、解码长度与协议参数一致（如多项式长度、压缩位数）
///   - @kem 系列辅助函数已正确定义（如 NTT、采样、压缩、PRF 等）
///
/// Description
///
/// 实现基于格的 KEM 算法的加密流程：
///
/// 1. **公钥解码**：
///    - 从公钥 ek_PKE 解压 t_hat（多项式向量）和 rho（公钥种子）
///
/// 2. **公钥矩阵 Â 重建**：
///    - 用 rho、i、j 组合采样，恢复公钥 NTT 域矩阵 a_hat
///
/// 3. **采样 y, e₁, e₂**：
///    - 用 r 作为种子，PRF 采样噪声多项式向量 y、e₁，标量 e₂
///
/// 4. **变换 y -> ŷ（NTT 域）**
///
/// 5. **u 计算**：
///    - u[i] = NTT⁻¹( sum_j â[i][j] ∘ ŷ[j] ) + e₁[i]
///
/// 6. **v 计算**：
///    - v = NTT⁻¹( sum_j t̂[j] ∘ ŷ[j] ) + e₂ + μ
///    - μ 为明文 m 的解压缩多项式表示
///
/// 7. **密文编码**：
///    - u[i] 多项式和 v 多项式分别压缩为字节数组拼接成密文 c
///
/// 本加密流程对应 Kyber/PQ-KEM 类算法的原理。安全性来自多项式乘法和随机噪声采样的难以逆向。
///
/// Example
/// ```
/// let c = encrypt(ek_PKE, m, r)
/// ```
pub fn encrypt(ek_PKE : ByteArray, m : ByteArray, r : ByteArray) -> ByteArray {
  let k = 4
  // 1. 解码 t_hat
  let t_hat = []
  for i = 0; i < k; i = i + 1 {
    let offset = i * (256 * 12 / 8)
    let buf = ek_PKE[offset:offset + 256 * 12 / 8].iter().collect()
    let poly = Array::make(256, 0)
    @kem.poly_decompress(poly, buf, 12)
    t_hat.push(poly)
  }
  let rho = ek_PKE[384 * k:384 * k + 32].iter().collect()

  // 2. 生成 Â
  let a_hat = Array::make(k, Array::make(k, Array::make(256, 0)))
  for i = 0; i < k; i = i + 1 {
    for j = 0; j < k; j = j + 1 {
      let seed_a = rho.copy()
      seed_a.push(j.to_byte())
      seed_a.push(i.to_byte())
      a_hat[i][j] = @kem.sample_ntt(seed_a)
    }
  }

  // 3. 采样 y, e1, e2
  let y = []
  let n = 0
  for i = 0; i < k; i = i + 1 {
    let buf = @kem.prf(@kem.PARAM_ETA1, r, (n + i).to_byte())
    y.push(@kem.sample_poly_cbd(buf))
  }
  let e1 = []
  for i = 0; i < k; i = i + 1 {
    let buf = @kem.prf(@kem.PARAM_ETA2, r, (n + k + i).to_byte())
    e1.push(@kem.sample_poly_cbd(buf))
  }
  let buf = @kem.prf(@kem.PARAM_ETA2, r, (n + 2 * k).to_byte())
  let e2 = @kem.sample_poly_cbd(buf)

  // 4. NTT(y)
  let y_hat = []
  for i = 0; i < k; i = i + 1 {
    y_hat.push(@kem.ntt(y[i]))
  }

  // 5. u = NTT^{-1}(Â∘ŷ) + e₁
  let u = []
  for i = 0; i < k; i = i + 1 {
    let acc = Array::make(256, 0)
    for j = 0; j < k; j = j + 1 {
      let prod = @kem.ntt_pointwise_mul(a_hat[i][j], y_hat[j], @kem.PARAM_Q)
      if j == 0 {
        @kem.poly_copy(acc, prod)
      } else {
        @kem.poly_add(acc, acc, prod)
      }
    }
    let acc2 = @kem.intt(acc)
    @kem.poly_add(acc2, acc2, e1[i])
    u.push(acc2)
  }

  // 6. v = NTT^{-1}(t̂∘ŷ) + e₂ + μ
  let mu = Array::make(256, 0)
  @kem.poly_decompress(mu, m, 1)
  let acc = Array::make(256, 0)
  for j = 0; j < k; j = j + 1 {
    let prod = @kem.ntt_pointwise_mul(t_hat[j], y_hat[j], @kem.PARAM_Q)
    if j == 0 {
      @kem.poly_copy(acc, prod)
    } else {
      @kem.poly_add(acc, acc, prod)
    }
  }
  let v = @kem.intt(acc)
  @kem.poly_add(v, v, e2)
  @kem.poly_add(v, v, mu)

  // 7. 编码输出密文
  let c1 = []
  for i = 0; i < k; i = i + 1 {
    let buf : Array[Byte] = Array::make(256 * 6 / 8, 0)
    @kem.poly_compress(buf, u[i], 6)
    c1.append(buf)
  }
  let c2 : Array[Byte] = Array::make(256 * 6 / 8, 0)
  @kem.poly_compress(c2, v, 6)
  let c = []
  c.append(c1)
  c.append(c2)
  c
}

///| 格密码 KEM 私钥解密函数（Decryption for Lattice-based KEM）  
///
/// Parameters
///
/// - `dk_PKE` : 私钥字节数组（ByteArray），由 keygen 生成（包含 ŝ）
/// - `c` : 密文字节数组（ByteArray），由 encrypt 生成
///
/// Returns
///
/// - `ByteArray` : 恢复出的明文消息（压缩后的 32 字节多项式编码）
///
/// Errors
///
/// - 无显式错误抛出，但依赖：
///   - 密钥、密文格式与参数一致（如多项式长度、压缩位数）
///   - @kem 系列辅助函数（如 NTT、NTT 逆、解压缩、编码、压缩等）已正确定义
///
/// Description
///
/// 实现格基 KEM 算法的解密过程，步骤如下：
///
/// 1. **拆分密文**：
///    - 按参数提取 c1（u' 向量）与 c2（v' 多项式）
///
/// 2. **解码 u' 向量**：
///    - 每个分量解压缩为 256 维多项式
///
/// 3. **解码 v' 多项式**：
///    - 解压缩为 256 维多项式
///
/// 4. **解码私钥 ŝ**：
///    - 按 12 位压缩格式解码，恢复 NTT 域私钥向量
///
/// 5. **NTT(u')**：
///    - 对每个 u' 分量进行 NTT 变换
///
/// 6. **多项式积求和并逆变换**：
///    - 计算 sum_i ŝ[i] ∘ NTT(u'[i])，再做 NTT⁻¹
///
/// 7. **恢复明文前态**：
///    - w = v' - t
///
/// 8. **压缩编码消息**：
///    - 对 w 多项式用 1 位压缩编码，返回 32 字节消息
///
/// 该过程对应于 Kyber/PQ-KEM 类格密码解密流程，安全性依赖于多项式运算和噪声难以反演。
///
/// Example
/// ```
/// let m = decrypt(dk_PKE, c)
/// ```
pub fn decrypt(dk_PKE : ByteArray, c : ByteArray) -> ByteArray {
  let k = 4
  let d_u = 6
  let d_v = 6

  // 1. 拆分密文
  let c1_len = 32 * d_u * k
  let c2_len = 32 * d_v
  let c1 = c[0:c1_len].iter().collect()
  let c2 = c[c1_len:c1_len + c2_len].iter().collect()

  // 2. 解码 u'
  let u_prime = []
  for i = 0; i < k; i = i + 1 {
    let offset = i * (256 * d_u / 8)
    let buf = c1[offset:offset + 256 * d_u / 8].iter().collect()
    let poly = @kem.byte_decode(buf, d_u)
    let poly2 = Array::make(256, 0)
    @kem.poly_decompress(poly2, buf, d_u)
    u_prime.push(poly2)
  }

  // 3. 解码 v'
  let v_prime_poly = @kem.byte_decode(c2, d_v)
  let v_prime = Array::make(256, 0)
  @kem.poly_decompress(v_prime, c2, d_v)

  // 4. 解码私钥 ŝ
  let s_hat = []
  for i = 0; i < k; i = i + 1 {
    let offset = i * (256 * 12 / 8)
    let buf = dk_PKE[offset:offset + 256 * 12 / 8].iter().collect()
    let poly = @kem.byte_decode(buf, 12)
    s_hat.push(poly)
  }

  // 5. 计算 NTT(u')
  let u_prime_hat = []
  for i = 0; i < k; i = i + 1 {
    u_prime_hat.push(@kem.ntt(u_prime[i]))
  }

  // 6. 计算 ŝ^T ∘ NTT(u')，再 NTT^{-1}
  let acc = Array::make(256, 0)
  for i = 0; i < k; i = i + 1 {
    let prod = @kem.ntt_pointwise_mul(s_hat[i], u_prime_hat[i], @kem.PARAM_Q)
    if i == 0 {
      @kem.poly_copy(acc, prod)
    } else {
      @kem.poly_add(acc, acc, prod)
    }
  }
  let t = @kem.intt(acc)

  // 7. w = v' - t
  let w = Array::make(256, 0)
  @kem.poly_sub(w, v_prime, t)

  // 8. m = ByteEncode_1(Compress_1(w))
  let buf : Array[Byte] = Array::make(256 * 1 / 8, 0)
  @kem.poly_compress(buf, w, 1)
  // 直接返回压缩后的 32 字节消息
  buf
}
