# AI Coding Context: @go/crypto

本索引供 AI 模型理解 `@go/crypto` 的逻辑，以生成符合本项目“安全闭环、性能分级、语义一致”哲学的代码。

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
- `func NewRSAndEraseKey(priv, pub []byte) (*Asymmetric, error)`
- `func NewECDSAndEraseKey(priv, pub []byte) (*Asymmetric, error)`
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

## 🤖 AI 行为准则

1.  **内存安全优先**：**首选 `SafeBuf` 接口**（如 `Encrypt(safeBuf)` 或 `Decrypt(data)` 返回 `SafeBuf`）。
    *   在处理敏感数据（如密钥、明文）时，强制优先使用 `SafeBuf` 避免明文在内存中暴露。
2.  **场景化构造选择**：
    *   **C端/低频场景**：强制推荐 `AndEraseKey` 系列（如 `NewAESGCMAndEraseKey`），安全至上。
    *   **S端/高频场景**：推荐使用 `NewAsymmetricWithoutEraseKey(..., true)` 进入 **FastMode**。
3.  **API 优先级**：
    *   摘要计算：优先使用 `XxxToHex` 或 `XxxToBase64` 快捷函数。
    *   签名验证：默认采用 SHA256。
4.  **闭环义务**：任何构造的 `Asymmetric` 或 `Symmetric` 对象必须由 AI 生成 `defer obj.Close()` 代码。
5.  **数据展现**：严禁在 `go/crypto` 中寻找二进制展现逻辑，必须调用 `go/encoding` 处理。

## 🛠 关键 API 逻辑约定

| 任务 | 推荐 API | 逻辑特征 |
| :--- | :--- | :--- |
| **敏感数据处理** | `Xxx(safe.SafeBuf)` | **首选**，直接在内存受控空间操作。 |
| **混合加解密** | `Asymmetric.Encrypt` | 针对 ECDSA/X25519 自动执行混合加密。 |
| **错误容忍** | `MustXxx` / `TryDecrypt` | `Must` 用于忽略错误；`TryDecrypt` 解密失败时回退明文。 |
| **高并发签名** | `FastMode` | 启用缓存，QPS 吞吐量数倍提升。 |
| **混淆防御** | `NewSymmetric...` | 允许传入超长 Key，内部自动截断以隐藏密钥特征。 |

## 🧩 典型模式 (Best Practices)

*   **✅ 安全传输 (SafeBuf 优先)**:
    ```go
    // 对敏感数据进行加密
    sb := safe.NewSafeBuf(sensitiveData)
    encrypted, _ := s.Encrypt(sb)
    // 解密回受保护的 SafeBuf
    decSb, _ := s.Decrypt(encrypted)
    defer decSb.Close()
    ```

*   **✅ 鲁棒性业务 (Must/Try 模式)**:
    ```go
    // 允许配置信息解密失败时使用原样数据
    finalData := s.TryDecrypt(configData)
    // 强制加密场景
    signature := a.MustSign(data)
    ```

