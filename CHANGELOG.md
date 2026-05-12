# Changelog: @go/crypto

## [v1.1.2] - 2026-05-12

### Added
- **统一配置解密接口 (加固版)**：新增 `OnSetDefaultAES` 回调与 `SetDefaultAES` 注入接口。
- **极致内存安全**：`SetDefaultAES` 注入生产密钥后将**自动擦除** (ZeroMemory) 传入的密钥源字节，并**自动锁定**注册通道。
- **基础设施对齐**：同步更新 `redis`, `api`, `db`, `mail` 等项目，移除本地 `confAes`，全面接入安全加固后的 `crypto.confAES` 体系。

## [v1.1.1] - 2026-05-12

### Added
- **密码学强化**：新增基于 Argon2id 的密码派生密钥 (KDF) 支持。
- **便捷构造器**：新增 `New...ByPassword` 系列 API，支持通过密码与盐直接创建 AES (GCM/CBC)、RSA、ECDSA、Ed25519 及 X25519 实例。
- **确定性生成**：非对称算法（ECDSA, Ed25519, X25519）支持基于密码的确定性密钥对生成，确保多端/多次调用的一致性（注：RSA 因算法特性，其确定性受 Go 版本内部实现影响）。
- **强制内存安全**：所有 `ByPassword` 接口均强制执行 `EraseKey` 策略，派生完成后立即擦除原始密码与盐。

## [v1.0.6] - 2026-05-06

### Changed
- **设计哲学对齐**：全面废除 `Must` 前缀函数（`MustEncrypt`, `MustDecrypt`, `MustSign`, `MustVerify`），改为配合 `go/cast` 的 `As` 函数。
- **鲁棒性增强**：在 `AESCipher.Decrypt` (CBC 模式) 中增加数据长度校验，防止因输入非块大小倍数而导致的 Panic。

### Added
- **API 补全**：新增 `TryDecrypt` 方法，在解密失败时返回原始数据。
- **依赖对齐**：引入 `apigo.cc/go/cast` 依赖。

## [v1.0.5] - 2026-05-01
- (同步版本号)

## [v1.0.4] - 2026-05-01

### Fixed
- **命名规范优化**：修复了多个 `WithOut` -> `Without` 的拼写错误（涉及 AES, RSA, ECDSA, Ed25519, X25519 的构造器）。
- **接口对齐**：修复了 `NewRSAAndEraseKey` 和 `NewECDSAAndEraseKey` 遗漏 'A' 的问题。

### Optimized
- **填充性能**：使用 `bytes.Repeat` 优化 `Pkcs5Padding` 和 `AnsiX923Padding` 的执行效率。
- **并发安全性**：通过 Benchmark 验证了高并发场景下的稳定性。

## [v1.0.0] - 2026-04-22

### Added
- **核心算法支持**：提供 AES (CBC/GCM)、RSA (PSS/OAEP/PKCS1v15)、ECDSA、Ed25519、X25519 全量主流算法。
- **混合加密模式**：针对 ECDSA 和 X25519 实现了 ECDH + HKDF + AES-GCM/CBC 的自动化混合加解密。
- **填充算法增强**：新增 ANSI X9.23 填充支持，完善 PKCS#7 (Pkcs5) 填充。
- **内存安全集成**：深度集成 `@go/safe`，提供 `AndEraseKey` 构造器，实现密钥构造即擦除原始明文，杜绝内存残留。
- **混淆防御机制**：对称加密支持超长密钥自动截断适配，增强内存指纹抗性。
- **高性能模式 (FastMode)**：非对称加密支持可选的对象缓存模式，显著降低高频调用下的解析开销。
- **便捷 Hash 包装**：提供 MD5/SHA 家族的一键式 Hex/Base64 返回接口。
- **兼容性语义**：1:1 还原 `ssgo/u` 函数命名，确保业务迁移无感知。
