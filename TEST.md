# Test Report: @go/crypto

## 📋 测试概览
- **测试时间**: 2026-05-06
- **测试环境**: darwin/amd64
- **Go 版本**: 1.25.0

## ✅ 功能测试 (Functional Tests)
| 场景 | 状态 | 描述 |
| :--- | :--- | :--- |
| `TestSymmetric` | PASS | AES-CBC/GCM 加解密往返测试。 |
| `TestAsymmetric` | PASS | RSA, ECDSA, Ed25519, X25519 签名与加解密测试。 |
| `TestMustAndTryMethods` | PASS | 配合 `cast.As` 消除摩擦及 `TryDecrypt` 逻辑测试。 |
| `TestSecurityErase` | PASS | 密钥内存安全擦除验证。 |

## 🛡️ 鲁棒性防御 (Robustness)
- **Panic 防御**：在 CBC 模式解密中强制校验块对齐，拦截底层库可能抛出的 Panic。
- **内存安全**：基于 `go/safe` 的密钥管理与自动释放。

## ⚡ 性能基准 (Benchmarks)
| 函数 | 平均耗时 | 性能分析 |
| :--- | :--- | :--- |
| `AES_GCM` | **4805 ns/op** | 性能优异。 |
| `RSA_Sign` | **1349477 ns/op** | 复合 RSA 标准耗时。 |
| `Ed25519_Sign` | **26689 ns/op** | 高性能签名。 |
