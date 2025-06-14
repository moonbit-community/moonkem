///| KEM 高层内部密钥对生成函数（Internal Key Generation for KEM）  
///
/// Parameters
///
/// - `d` : 字节数组（ByteArray），作为 PKE 密钥对生成的主熵源
/// - `z` : 字节数组（ByteArray），用于私钥扩展部分的附加随机值
///
/// Returns
///
/// - `(ByteArray, ByteArray)` : 返回二元组 (ek, dk)
///   - `ek` ：扩展公钥字节数组（即 ek_PKE）
///   - `dk` ：扩展私钥字节数组（格式为 dk_PKE || ek || H(ek) || z）
///
/// Errors
///
/// - 无显式错误抛出，但依赖：
///   - `keygen`、`@kem.h` 等函数已正确定义
///   - 输入参数长度和内容均满足协议要求
///
/// Description
///
/// 此函数为 KEM（密钥封装机制）生成扩展密钥对，包含如下步骤：
///
/// 1. **生成 PKE 密钥对**：
///    - 调用 `keygen(d)` 得到基础公私钥对 (`ek_PKE`, `dk_PKE`)
///
/// 2. **扩展公钥**：
///    - 直接取 `ek_PKE` 作为 KEM 的公钥 ek
///
/// 3. **扩展私钥**：
///    - 私钥 dk 结构为：`dk_PKE || ek || H(ek) || z`
///    - 其中 H(ek) 表示对公钥 ek 的哈希
///    - z 为外部附加的私钥熵源，常用于防护故障攻击或密钥更新
///
/// 4. **返回密钥对**
///
/// Example
/// ```
/// let (ek, dk) = keygen_internal(d, z)
/// ```
pub fn keygen_internal(d : ByteArray, z : ByteArray) -> (ByteArray, ByteArray) {
  // 1. K-PKE 密钥对生成
  let (ek_PKE, dk_PKE) = keygen(d)
  // 2. ek = ek_PKE
  let ek = ek_PKE
  // 3. dk = dk_PKE || ek || H(ek) || z
  let h_ek = @kem.h(ek)
  let dk = dk_PKE.copy()
  dk.append(ek)
  dk.append(h_ek)
  dk.append(z)
  // 4. 返回
  (ek, dk)
}

///| KEM 内部封装函数（Internal Encapsulation for KEM）  
///
/// Parameters
///
/// - `ek` : 扩展公钥字节数组（ByteArray），由 `keygen_internal` 生成
/// - `m`  : 封装用的消息随机数（ByteArray），一般为临时生成的随机数或密钥材料
///
/// Returns
///
/// - `(ByteArray, ByteArray)` : 返回二元组 (K, c)
///   - `K` ：协商出的密钥（ByteArray），用于对称加密等
///   - `c` ：密文（ByteArray），用于安全传输
///
/// Errors
///
/// - 无显式错误抛出，但依赖：
///   - `@kem.h`、`@kem.g`、`encrypt` 等函数已正确定义且安全
///   - 输入参数格式与协议一致
///
/// Description
///
/// 此函数实现 KEM 协议中的内部封装过程：
///
/// 1. **密钥派生与随机数生成**：  
///    - 令 `input = m || H(ek)`，即消息与公钥哈希拼接  
///    - 通过派生函数 `@kem.g(input)`，得到协商密钥 K 和随机数 r  
///
/// 2. **加密消息**：  
///    - 用扩展公钥 ek、明文 m、随机数 r 调用 `encrypt`，生成密文 c  
///
/// 3. **返回 (K, c)**：  
///    - 输出 (K, c)，即 KEM 封装输出  
///
/// 该流程保障了密钥协商的随机性和密文不可区分性，常用于 PQ-KEM/格密码标准协议中。
///
/// Example
/// ```
/// let (K, c) = encaps_internal(ek, m)
/// ```
pub fn encaps_internal(ek : ByteArray, m : ByteArray) -> (ByteArray, ByteArray) {
  // 1. k, r ← G(m ∥ H(ek))
  let h_ek = @kem.h(ek)
  let input = m.copy()
  input.append(h_ek)
  let (k, r) = @kem.g(input)
  // 2. c ← K-PKE.Encrypt(ek, m, r)
  let c = encrypt(ek, m, r)
  // 3. 返回 (K, c)
  (k, c)
}

///| KEM 内部解封装函数（Internal Decapsulation for KEM）  
///
/// Parameters
///
/// - `dk` : 扩展私钥字节数组（ByteArray），由 `keygen_internal` 生成（含私钥、扩展公钥、哈希、随机熵）
/// - `c`  : 密文字节数组（ByteArray），由 `encaps_internal` 封装产生
///
/// Returns
///
/// - `ByteArray` : 协商出的对称密钥 K′（ByteArray），用于后续加密通信
///
/// Errors
///
/// - 无显式错误抛出，但依赖：  
///   - 密钥、密文格式与协议参数一致  
///   - @kem 相关函数（如 `decrypt`、`encrypt`、`g`、`j`、`constant_time_compare`）均已实现并安全  
///
/// Description
///
/// 实现 KEM 解封装（密钥恢复）过程，典型于 PQ-KEM/格密码协议，流程如下：
///
/// 1. **扩展私钥分解**：  
///    - dk_PKE    = dk 前 384k 字节（基础私钥）  
///    - ek_PKE    = dk 紧随其后的 384k+32 字节（公钥副本）  
///    - h         = dk 的 H(ek) 哈希字段  
///    - z         = dk 的随机熵字段  
///
/// 2. **明文恢复**：  
///    - 用私钥 dk_PKE 解密密文 c，得 m′  
///
/// 3. **协商密钥候选与随机数**：  
///    - k′, r′ = G(m′ ∥ h)，按 KEM 标准派生  
///
/// 4. **故障恢复密钥**：  
///    - k̄ = J(z ∥ c)，若密文校验失败，则返回该密钥  
///
/// 5. **密文重加密一致性校验**：  
///    - 用 ek_PKE、m′、r′ 重新加密，得 c′  
///    - 常数时间比对 c, c′：  
///       - 若一致，则返回 k′  
///       - 不一致，则返回 k̄（抗选择密文攻击，确保密钥不可区分）  
///
/// Example
/// ```
/// let K = decaps_internal(dk, c)
/// ```
pub fn decaps_internal(dk : ByteArray, c : ByteArray) -> ByteArray {
  let k = 4
  let d_u = 6
  let d_v = 6

  // 1. dk_PKE ← dk[0 : 384k]
  let dk_PKE = dk[0 : 384 * k].iter().collect()
  // 2. ek_PKE ← dk[384k : 768k+32]
  let ek_PKE = dk[384 * k : 768 * k + 32].iter().collect()
  // 3. h ← dk[768k+32 : 768k+64]
  let h = dk[768 * k + 32 : 768 * k + 64].iter().collect()
  // 4. z ← dk[768k+64 : 768k+96]
  let z = dk[768 * k + 64 : 768 * k + 96].iter().collect()

  // 5. m′ ← K-PKE.Decrypt(dk_PKE, c)
  let m_prime = decrypt(dk_PKE, c)
  // 6. (K′, r′) ← G(m′ ∥ h)
  let input = m_prime.copy()
  input.append(h)
  let (k_prime, r_prime) = @kem.g(input)
  // 7. K̄ ← J(z ∥ c)
  let zc = z.copy()
  zc.append(c)
  let k_bar = @kem.j(zc)
  // 8. c′ ← K-PKE.Encrypt(ek_PKE, m′, r′)
  let c_prime = encrypt(ek_PKE, m_prime, r_prime)
  // 9-11. if c ≠ c′ then K′ ← K̄
  let k_final = if @kem.constant_time_compare(c, c_prime) {
    k_prime
  } else {
    k_bar
  }
  // 12. return K′
  k_final
}