# moonkem

moonkem 是一套用 Moonbit 语言实现的 [ML-KEM (CRYSTALS-Kyber)](https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2022) 格基密钥封装机制（KEM）库，支持高安全性、抗量子攻击的密钥协商、加密与解密。  
本库结构清晰，注释详尽，适合科研、教学、工程实践和标准兼容性测试。

---

## ✨ 特性亮点

- **标准兼容**：严格实现 NIST FIPS 203 ML-KEM (Kyber) 标准，接口与流程与官方一致
- **高安全性**：全流程采用系统级 CSPRNG，安全强度可达 256 bit，抗量子攻击
- **模块化设计**：密钥生成、封装、解封装、底层多项式与NTT操作全部模块化，便于维护和扩展
- **易用接口**：一行代码即可完成密钥协商，API 友好
- **详细注释与文档**：每个核心算法均有详细文档和注释，便于学习与二次开发
- **一致性检查**：内置密钥对一致性检查，便于测试和安全验证
- **参数可配置**：支持 Kyber512、Kyber768、Kyber1024 等多种安全级别

---

## 📦 安装与依赖

moonkem 依赖 Moonbit 语言环境。  
请确保已安装 [Moonbit](https://moonbitlang.cn/) 编译器和标准库。

---

## 🚀 快速上手

### 1. 生成密钥对

```moonbit
let (ek, dk) = @moonkem.ml_keygen()
// ek: 封装公钥（发送方用）
// dk: 解封装私钥（接收方用）
```

### 2. 封装（加密协商密钥）

```moonbit
let (K, c) = @moonkem.ml_encaps(ek)
// K: 协商出的共享密钥
// c: 密文（发送给接收方）
```

### 3. 解封装（解密恢复密钥）

```moonbit
let K2 = @moonkem.ml_decaps(dk, c)
// K2: 恢复出的共享密钥，理论上 K2 == K
```

### 4. 密钥对一致性检查

```moonbit
let ok = @moonkem.check_pairwise_consistency(ek, dk)
if ok {
  print("密钥对一致性通过")
} else {
  print("密钥对一致性失败")
}
```

---

## 🧩 主要接口说明

| 函数名                                      | 说明                                                         |
|---------------------------------------------|--------------------------------------------------------------|
| `ml_keygen()`                              | 生成密钥对 (ek, dk)                                          |
| `ml_encaps(ek)`                            | 封装，输出 (K, c)                                            |
| `ml_decaps(dk, c)`                         | 解封装，输出 K                                               |
| `check_pairwise_consistency(ek, dk)`        | 密钥对一致性检查                                             |
| `keygen_internal(d, z)`                    | 内部密钥生成（供标准一致性测试或种子一致性验证用）           |
| `encaps_internal(ek, m)`                   | 内部封装（自定义消息 m，供标准一致性测试用）                 |
| `decaps_internal(dk, c)`                   | 内部解封装（供标准一致性测试用）                             |
| `random_bytes(n)`                          | 生成 n 字节安全随机数，调用系统 CSPRNG                       |

---

## 🔒 安全性与实现细节

- **随机数生成**  
  - 所有密钥、消息、随机因子均调用系统级 CSPRNG（符合 NIST SP 800-90A/B/C），安全强度可达 256 bit
  - 每次封装、密钥生成都生成全新随机数，绝不复用
- **常数时间比较**  
  - 所有密钥、密文比较均采用常数时间算法，防止侧信道攻击
- **参数可配置**  
  - 支持 Kyber512、Kyber768、Kyber1024，参数可在 `ntt.mbt` 中配置
- **多项式与NTT优化**  
  - 多项式加减、NTT/INTT、点乘、压缩/解压等均有独立模块，便于替换和优化
- **编码与压缩**  
  - 所有多项式、密钥、密文均采用标准压缩与编码，兼容官方实现

---

## 📁 目录结构

```
moonkem/
├── src/
│   ├── keys/             # KEM高层接口与密钥管理
│   │   ├── ml-kem.mbt    # ML-KEM高层接口
│   │   └── k-pke.mbt     # K-PKE底层接口
│   ├── ntt.mbt           # NTT与多项式运算
│   ├── poly.mbt          # 多项式基本操作
│   ├── auxiliary.mbt     # 辅助函数与类型
│   ├── conversion.mbt    # 编解码与压缩
│   └── ...
└── README.md
```

---

## 📚 参考文献与标准

- [NIST PQC ML-KEM (Kyber) 标准 FIPS 203](https://csrc.nist.gov/publications/detail/fips/203/final)
- [CRYSTALS-Kyber 官方文档](https://pq-crystals.org/kyber/)
- [SP 800-90A/B/C 随机数标准](https://csrc.nist.gov/publications/sp)
- [Kyber 论文与安全分析](https://pq-crystals.org/kyber/data/kyber-specification-round3.pdf)

---

## 🤝 贡献与反馈

- 欢迎 issue、PR 或建议，帮助本库更完善！
- 如需定制、代码讲解或安全审计，请联系作者。
- 本库适合科研、教学、工程实践和标准兼容性测试。

---

## 📝 License

Apache License 2.0 © International Digital Economy Academy

---

**moonkem** —— 让抗量子安全变得简单、优雅、可验证。  
Moonbit 生态下的高质量格基密钥封装库。