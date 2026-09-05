# Test Report: @go/crypto

## v1.5.6 验证
- 全量测试与基准测试通过；密码派生非对称密钥回归连续运行 10 次通过。

## 📋 测试概览
- **测试时间**: 2026-06-21
- **测试环境**: darwin/amd64
- **Go 版本**: 1.25.0

## ✅ 功能测试 (Functional Tests)
| 场景 | 状态 | 描述 |
| :--- | :--- | :--- |
| `TestSymmetric` | PASS | AES-CBC/GCM 加解密往返测试。 |
| `TestAsymmetric` | PASS | RSA, ECDSA, Ed25519, X25519 签名与加解密测试。 |
| `TestMustAndTryMethods` | PASS | 配合 `cast.As` 消除摩擦及 `TryDecrypt` 逻辑测试。 |
| `TestSecurityErase` | PASS | 密钥内存安全擦除验证。 |
| `TestPasswordBased` | PASS | 基于密码 (Argon2id) 的对称与非对称密钥派生功能测试。 |
| `TestDeterministic` | PASS | 非对称密钥基于密码的确定性生成验证。 |

## 🛡️ 鲁棒性防御 (Robustness)
- **Panic 防御**：在 CBC 模式解密中强制校验块对齐，拦截底层库可能抛出的 Panic。
- **内存安全**：基于 `go/safe` 的密钥管理与自动释放。

## ⚡ 性能基准 (Benchmarks)
| 函数 | 平均耗时 | 性能分析 |
| :--- | :--- | :--- |
| `AES_GCM` | **4854 ns/op** | 性能优异。 |
| `RSA_Sign` | **1407588 ns/op** | 符合 RSA 标准耗时。 |
| `Ed25519_Sign` | **28299 ns/op** | 高性能签名。 |
| `X25519_Encrypt` | **204639 ns/op** | 混合加密模式性能表现。 |
