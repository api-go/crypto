# Test Report: @go/crypto

## v1.5.9 发布验证（2026-10-26）

Go 1.26.4 / darwin arm64 / Apple M3 Max，GOWORK=off，使用已发布依赖，无 replace。
`go test -v ./...`、`go test -bench=. ./...`、`go test -race ./...`、`go vet ./...` 通过。
使用 `go doc` / `go doc Symmetric` 与导出源码交叉核对 API，替代 getExports 工具。
新增覆盖：0/1/11/12/15/16/17/128/4096 字节；独立标准库解密新格式；旧格式逐字节保持；
不同实例与仅 key 解密；nonce 唯一性；nonce/正文/tag 篡改、错误 key、短数据与短 IV；
旧密文前缀碰撞回退；SafeBuf、成功/失败擦除、并发；原接口自定义算法兼容，CBC 自动 IV 拒绝。

同层 Symmetric 解密基准（时间为单次，包含 SafeBuf 开销）：

| 明文长度 | 原显式 IV | 兼容解密旧格式 | 兼容解密自动 IV |
| --- | --- | --- | --- |
| 64 B | 1.884 µs | 1.905 µs | 1.876 µs |
| 4 KiB | 2.581 µs | 3.406 µs | 2.696 µs |
| 1 MiB | 175.975 µs | 340.643 µs | 165.718 µs |

1 MiB 新格式约 1 MiB 分配，旧格式回退约 2 MiB；数据量越大，额外认证处理越明显。
微小时间差受运行噪声影响，不表示新格式必然更快。完整原始输出在本次本机 `/tmp/go-crypto-bench.log`。

## Unreleased 验证
- `TestSymmetricDeriveKey` 验证相同用途稳定派生、不同用途域隔离、输出长度和非法长度拒绝。

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

## GitHub migration validation (pending release)

Module paths and internal dependency versions are migrated. Development verification uses GOWORK=off and explicit sibling replacements; remove these replacements before release. See migration validation logs for actual results. Existing unrelated working changes are preserved and require separate review.

API inventory verification: `GOWORK=off go doc` succeeded; output retained in the migration validation directory. Source exports were preserved by the path migration.

## GitHub release verification

GOWORK=off go test -v ./... and go test -bench=. ./... passed using published GitHub dependencies, without local replacements. go mod verify passed.
