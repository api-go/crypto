# Test Report: @go/crypto

## 📋 测试概览
- **测试时间**: 2026-04-22
- **测试环境**: darwin/amd64
- **Go 版本**: 1.25.0

## ✅ 功能测试 (Functional Tests)
| 场景 | 状态 | 描述 |
| :--- | :--- | :--- |
| `TestRSA_AllModes` | PASS | 覆盖 RSA PSS/OAEP 以及 FastMode 缓存模式。 |
| `TestECDSA_Hybrid` | PASS | 验证 ECDH + HKDF + AESGCM 混合加解密链路。 |
| `TestEd25519` | PASS | 纯签名/验签逻辑验证。 |
| `TestX25519_Hybrid` | PASS | 验证 X25519 混合加解密链路。 |
| `TestSecurityErase` | PASS | **核心安全测试**：验证 `AndEraseKey` 调用后原始密钥内存确实被物理擦除。 |
| `TestSymmetricObfuscation` | PASS | 验证传入 64 字节混淆密钥时，自动截断适配 32 字节 AES 密钥的逻辑。 |
| `TestAnsiX923Padding` | PASS | 验证 ANSI X9.23 填充算法的一致性。 |
| `TestConcurrentSafe` | PASS | 验证 `Symmetric` 对象在高并发环境下的数据隔离与安全性。 |
| `TestHashCompatibility` | PASS | 确保封装的 Hash API 与标准库 MD5/SHA256/HMAC 结果 1:1 对齐。 |

## 🛡️ 鲁棒性防御 (Robustness)
- **密钥混淆**：支持超长密钥输入以混淆内存特征，内部自动适配 16/24/32 字节核心密钥。
- **故障静默**：`DecryptBytesN` 在填充或密文损坏时静默返回原始数据，防止业务因加密错误崩溃。
- **哈希安全**：RSA/ECDSA 签名强制默认 SHA256，防止因哈希未指定导致的空指针 Panic。

## ⚡ 性能基准 (Benchmarks)
| 算法类型 | 耗时 (ns/op) | 性能倍率 (对比 RSA) | 结论 |
| :--- | :--- | :--- | :--- |
| **Ed25519 签名** | **~27938** | **50.0x** | **性能冠军**，极力推荐。 |
| **ECDSA 签名** | **~54753** | **25.5x** | 现代 Web 标准，性能卓越。 |
| **X25519 混合加密** | **~216035** | **6.5x** | 适合非对称大数据量加密。 |
| **RSA-2048 签名** | **~1397766**| **1.0x** | **性能瓶颈**，仅建议用于兼容。 |
| **AES-GCM** | **~4562** | - | 优于 CBC，首选对称算法。 |

> **首席架构师建议**：
> 1. 云端高并发：优先 Ed25519 签名 + AES-GCM 对称加密。
> 2. 传统兼容：使用 RSA-2048 + FastMode。
> 3. 混合加密：大数据量直接用 X25519/ECDSA 的 `Encrypt` 方法。
