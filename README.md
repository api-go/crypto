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
go get apigo.cc/go/crypto
```

## 💡 示例 (配合 cast.As 消除摩擦)

```go
import (
    "apigo.cc/go/crypto"
    "apigo.cc/go/cast"
)

// 使用 cast.As 替代原有的 MustEncrypt 系列
cipher, _ := crypto.NewAESCBCAndEraseKey(key, iv)
ciphertext := cast.As(cipher.EncryptBytes(plaintext))
```
