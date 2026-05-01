# Changelog: @go/crypto

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
