# 关于本项目

本项目完全由 AI 维护。代码源自 github.com/ssgo/u 的重构。

# @go/crypto

`@go/crypto` 是一个为“安全闭环、消除摩擦”设计的加密工具库。它强制执行内存安全（基于 `go/safe`）与资源自动回收，并提供语义化的加解密与 Hash API。

## 🎯 设计哲学

*   **内存安全闭环**：通过 `safe.SafeBuf` 保护密钥，确保敏感数据在内存中加密存储，并在使用后自动/手动擦除，防止内存 Dump 攻击。
*   **消除摩擦 (Frictionless)**：废除 `Must` 前缀函数，全面结合 `go/cast` 的 `As` 函数。
*   **资源自动回收**：利用 `runtime.SetFinalizer` 确保加密实例在垃圾回收时自动释放密钥资源。
*   **高性能混合体系**：内置 AES (CBC/GCM)、RSA (PSS/OAEP)、ECDSA、Ed25519、X25519，支持 FastMode 缓存解析结果。

## 🛠 API Reference

### 对称加密 (Symmetric)
- `func NewAESCBC(safeKeyBuf, safeIvBuf *safe.SafeBuf) (*Symmetric, error)`
- `func NewAESCBCAndEraseKey(key, iv []byte) (*Symmetric, error)`
- `func NewAESCBCByPassword(password, salt []byte) (*Symmetric, error)` (Argon2id 驱动)
- `func NewAESGCMByPassword(password, salt []byte) (*Symmetric, error)` (Argon2id 驱动)
- `func (s *Symmetric) EncryptBytes(data []byte) ([]byte, error)`
- `func (s *Symmetric) DecryptBytes(data []byte) ([]byte, error)`
- `func (s *Symmetric) TryDecrypt(data []byte) []byte` (解密失败返回原始数据)
- `func (s *Symmetric) DeriveKey(info []byte, size int) (*safe.SafeBuf, error)`（使用 HKDF-SHA256 从受保护主密钥派生用途隔离的子密钥）

### 推荐：AES-GCM 自动 IV

新数据优先使用 `EncryptBytesAutoIV`，不要在同一密钥下重复使用固定 IV。

```go
s, err := crypto.NewAESGCMWithoutEraseKey(key, legacyIV) // 仅新格式可传 nil IV
if err != nil { return err }
defer s.Close()
encrypted, err := s.EncryptBytesAutoIV(plaintext)
// 接收端使用相同 key；读取旧数据仍需配置原 IV。
plaintext, err = s.DecryptBytes(encrypted)
```

- `EncryptAutoIV(data *safe.SafeBuf) ([]byte, error)`
- `EncryptBytesAutoIV(data []byte) ([]byte, error)`
- `EncryptAndEraseAutoIV(data []byte) ([]byte, error)`：成功或失败均擦除明文。
- 输出固定为 `[12 字节随机 IV][密文正文][16 字节认证 tag]`，无格式头、无填充；总长为明文长度 + 28。可与标准 GCM 跨语言互操作。
- 同一 key 的随机 IV 加密总量不得超过 2^32 条；多实例/多进程累计计数，提前轮换 key。历史固定 IV 重复使用的风险不能由新格式修复，迁移建议换 key。
- 原 `Encrypt` / `EncryptBytes` / `EncryptAndErase` 继续使用配置 IV，保留旧输出格式。仅用于兼容或调用方保证 IV 唯一的协议。
- `Decrypt` / `DecryptBytes` 先认证内嵌 IV 格式，失败后使用配置 IV 认证旧格式；至少 28 字节的旧密文最多处理两次，均失败返回错误。`TryDecrypt` 保留失败返回原数据的旧契约，不能用来判断认证成功。
- 底层 `AESGCM.Encrypt/Decrypt(data, key, iv)` 保持显式 IV 格式，不进行自动识别。短 GCM IV 返回错误；旧的超长 IV 仍取前 12 字节。
- 公共层通过可选 `AutoIVCipher` 接口调度，不修改 `SymmetricCipher`；首批支持 AES-GCM。CBC 自动 IV 返回 `ErrNotImplemented`，不静默降级；其他自定义算法需实现该可选能力。
- JavaScript：新增 `EncryptAutoIV(data, key)`，现有 `Decrypt(data, key, iv)` 同样兼容两种格式（仅新格式时 IV 可传空）。
- 自动 IV 不修改实例 IV，`DeriveKey` 的派生结果不变；并发操作可用，但不要与 `Close` 并发。
- 先升级接收端 crypto，再开启发送端自动 IV；旧版本无法读取新格式。CBC/SM4、ECDSA/X25519 混合封装不变。

### 非对称加密与签名 (Asymmetric)
- `func NewRSA(safePrivateKeyBuf, safePublicKeyBuf *safe.SafeBuf) (*Asymmetric, error)`
- `func NewRSAByPassword(password, salt []byte, bitSize ...int) (*Asymmetric, error)` (Argon2id 确定性生成)
- `func NewECDSAByPassword(password, salt []byte, bitSize ...int) (*Asymmetric, error)` (确定性生成)
- `func NewED25519ByPassword(password, salt []byte) (*Asymmetric, error)` (确定性生成)
- `func NewX25519ByPassword(password, salt []byte) (*Asymmetric, error)` (确定性生成)
- `func (a *Asymmetric) Sign(data []byte, hash ...crypto.Hash) ([]byte, error)`
- `func (a *Asymmetric) Verify(data, signature []byte, hash ...crypto.Hash) (bool, error)`
- `func (a *Asymmetric) EncryptBytes(data []byte) ([]byte, error)`
- `func (a *Asymmetric) DecryptBytes(data []byte) ([]byte, error)`

### 密钥生成
- `func GenerateRSAKeyPair(bitSize int) (priv, pub []byte, err error)`
- `func GenerateECDSAKeyPair(bitSize int) (priv, pub []byte, err error)`
- `func GenerateEd25519KeyPair() (priv, pub []byte, err error)`
- `func GenerateX25519KeyPair() (priv, pub []byte, err error)`

### 全局配置解密 (Default AES)
为实现全项目配置解密的统一管理与生产环境密钥注入，提供以下全局接口：
- `var DefaultAES *Symmetric`：全局默认 AES 实例（初始使用内置硬编码密钥）。
- `func OnSetDefaultAES(h func(*Symmetric))`：注册 `DefaultAES` 变更回调。
- `func SetDefaultAES(key, iv []byte)`：注入生产环境密钥并触发所有回调更新。

### 哈希算法 (Hash)
- `func MD5(data []byte) []byte`
- `func SHA256(data []byte) []byte`
- `func HMACSHA256(data, key []byte) []byte`

## 📦 安装

```bash
go get github.com/api-go/crypto
```

## 💡 示例 (配合 cast.As 消除摩擦)

```go
import (
    "github.com/api-go/crypto"
    "github.com/api-go/cast"
)

// 使用 cast.As 替代原有的 MustEncrypt 系列
cipher, _ := crypto.NewAESGCMAndEraseKey(key, iv)
ciphertext := cast.As(cipher.EncryptBytesAutoIV(plaintext))
```

## SafeBuf 默认 AES 注入（v1.5.11）

`SetDefaultAESFromSafeBuf(key, iv *safe.SafeBuf) error` 接受独立的 SafeBuf；key 长度为 16/24/32，IV 长度为 12–16。成功后默认 AES 接管两个对象，调用方不得再 Close 或修改；失败时调用方负责 Close。与 SetDefaultAES 共用一次设置限制，设置成功后锁定观察者注册。观察者须在包变量初始化期间注册，不得在回调内重新设置。新入口对重复设置返回错误，旧入口保留原行为。

该入口避免导出模板接触明文，但长度校验及实际运算仍在库内部短暂打开秘密，不保证进程内攻击防御。现有 SetDefaultAES 的切片输入及擦除契约不变。自包含 Go 导出需配合 safe v1.5.6、keys v1.5.13。

Development verification now replaces the complete pending dependency graph, not only safe/crypto. All absolute-path replacements are temporary and must be removed in dependency order before release.

Release v1.5.11: verified with published dependencies and GOWORK=off; all temporary replacements have been removed. Earlier development-validation notes describe historical local checks.
