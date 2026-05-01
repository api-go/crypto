# 关于本项目
本项目完全由 AI 维护。代码源自 github.com/ssgo/u 的重构。

# @go/crypto

`@go/crypto` 是一个为“极速开发、内存级防御、全业务适配”设计的全功能加密工具库。它深度集成内存锁定与物理擦除技术，为金融级和 C 端运行环境提供了底层安全保障，同时为高并发服务端提供极致的性能模式。

## 🎯 设计哲学

*   **防御优先 (SafeMode)**：默认采用 `AndEraseKey` 范式，密钥构造即擦除原始明文，杜绝内存残留。
*   **性能巅峰 (FastMode)**：针对高并发场景（如 API 签名），提供对象缓存模式，显著降低 CPU 消耗。
*   **混合加解密**：原生支持非对称混合加密逻辑（ECDH + HKDF + AES），支持任意长度数据加密。
*   **混淆适配**：对称加密支持密钥自动截断，允许传入超长 buffer 以混淆内存特征。

## 🛠 API Reference

### 对称加密 (AES-CBC/GCM)
- `func NewAESCBCAndEraseKey(key, iv []byte) (*Symmetric, error)`
- `func NewAESGCMAndEraseKey(key, iv []byte) (*Symmetric, error)`
- `func (s *Symmetric) Encrypt(safeBuf *safe.SafeBuf) ([]byte, error)`
- `func (s *Symmetric) EncryptAndErase(data []byte) ([]byte, error)`
- `func (s *Symmetric) EncryptBytes(data []byte) ([]byte, error)`
- `func (s *Symmetric) MustEncrypt(data []byte) []byte`
- `func (s *Symmetric) Decrypt(data []byte) (*safe.SafeBuf, error)`
- `func (s *Symmetric) DecryptBytes(data []byte) ([]byte, error)`
- `func (s *Symmetric) MustDecrypt(data []byte) []byte`
- `func (s *Symmetric) TryDecrypt(data []byte) []byte`

### 非对称加密 (RSA/ECDSA/Ed25519/X25519)
- `func NewRSAAndEraseKey(priv, pub []byte) (*Asymmetric, error)`
- `func NewECDSAAndEraseKey(priv, pub []byte) (*Asymmetric, error)`
- `func NewED25519AndEraseKey(priv, pub []byte) (*Asymmetric, error)`
- `func NewX25519AndEraseKey(priv, pub []byte) (*Asymmetric, error)`
- `func NewAsymmetricWithoutEraseKey(algo, priv, pub, fastMode) (*Asymmetric, error)`
- `func (a *Asymmetric) Sign(data []byte, hash ...crypto.Hash) ([]byte, error)`
- `func (a *Asymmetric) SignAndErase(data []byte, hash ...crypto.Hash) ([]byte, error)`
- `func (a *Asymmetric) MustSign(data []byte, hash ...crypto.Hash) []byte`
- `func (a *Asymmetric) Verify(data, signature []byte, hash ...crypto.Hash) (bool, error)`
- `func (a *Asymmetric) MustVerify(data, signature []byte, hash ...crypto.Hash) bool`
- `func (a *Asymmetric) Encrypt(safeBuf *safe.SafeBuf) ([]byte, error)`
- `func (a *Asymmetric) EncryptAndErase(data []byte) ([]byte, error)`
- `func (a *Asymmetric) MustEncrypt(data []byte) []byte`
- `func (a *Asymmetric) Decrypt(data []byte) (*safe.SafeBuf, error)`
- `func (a *Asymmetric) DecryptBytes(data []byte) ([]byte, error)`
- `func (a *Asymmetric) MustDecrypt(data []byte) []byte`
- `func (a *Asymmetric) TryDecrypt(data []byte) []byte`

### Hash 系列 (MD5/SHA)
- `func MD5(data ...[]byte) []byte` / `func MD5ToHex(d []byte) string`
- `func Sha256ToHex(d []byte) string` / `func Sha256ToBase64(d []byte) string` / `func Sha256ToUrlBase64(d []byte) string`
- *其他算法 (Sha1, Sha512) 均支持上述 Hex/Base64/UrlBase64 变体*

### 密钥对生成
- `func GenerateRSAKeyPair(bitSize int) (priv, pub []byte, err error)`
- `func GenerateECDSAKeyPair(bitSize int) (priv, pub []byte, err error)`
- `func GenerateEd25519KeyPair() (priv, pub []byte, err error)`
- `func GenerateX25519KeyPair() (priv, pub []byte, err error)`

## 🚀 FastMode 性能模式
在高并发服务端对接场景中，内存被恶意扫描的风险极低，但 CPU 压力巨大。
Ed25519的非FastMode模式下性能也完全无损，强烈建议优先使用该算法。
**建议：** 使用 `NewAsymmetricWithoutEraseKey(..., true)`。
*   **效果**：缓存解析后的密钥对象。
*   **性能**：实测签名速度可提升数倍，相比默认模式能支持更高的 QPS。

## 📦 安装
```bash
go get apigo.cc/go/crypto
```
