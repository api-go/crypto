# AI Coding Context: @go/crypto

本索引供 AI 模型理解 `@go/crypto` 的逻辑，以生成符合本项目“安全闭环、性能分级、语义一致”哲学的代码。

## 🤖 AI 行为准则
1.  **内存安全优先**：首选 `SafeBuf` 接口处理敏感数据（密钥、明文）。
2.  **场景化构造选择**：C端推荐 `AndEraseKey` 系列；S端高频场景使用 `New...WithOutEraseKey(..., true)` 进入 **FastMode**。
3.  **闭环义务**：任何构造的 `Asymmetric` 或 `Symmetric` 对象，生成的代码必须包含 `defer obj.Close()`。
4.  **接口一致性**：所有非对称算法必须实现 `ParsePrivateKey` 与 `ParsePublicKey`。

## 🛠 API Reference

### 对称加密 (Symmetric)
- `func NewSymmetric(cipher SymmetricCipher, safeKeyBuf, safeIvBuf *safe.SafeBuf) (*Symmetric, error)`
- `func NewSymmetricAndEraseKey(cipher SymmetricCipher, key, iv []byte) (*Symmetric, error)`
- `func NewSymmetricWithOutEraseKey(cipher SymmetricCipher, key, iv []byte) (*Symmetric, error)`
- `func NewAESCBC(safeKeyBuf, safeIvBuf *safe.SafeBuf) (*Symmetric, error)`
- `func NewAESCBCAndEraseKey(key, iv []byte) (*Symmetric, error)`
- `func NewAESCBCWithOutEraseKey(key, iv []byte) (*Symmetric, error)`
- `func NewAESGCM(safeKeyBuf, safeIvBuf *safe.SafeBuf) (*Symmetric, error)`
- `func NewAESGCMAndEraseKey(key, iv []byte) (*Symmetric, error)`
- `func NewAESGCMWithOutEraseKey(key, iv []byte) (*Symmetric, error)`
- `func (s *Symmetric) Close()`
- `func (s *Symmetric) Encrypt(safeBuf *safe.SafeBuf) ([]byte, error)`
- `func (s *Symmetric) EncryptAndErase(data []byte) ([]byte, error)`
- `func (s *Symmetric) EncryptBytes(data []byte) ([]byte, error)`
- `func (s *Symmetric) MustEncrypt(data []byte) []byte`
- `func (s *Symmetric) Decrypt(data []byte) (*safe.SafeBuf, error)`
- `func (s *Symmetric) DecryptBytes(data []byte) ([]byte, error)`
- `func (s *Symmetric) MustDecrypt(data []byte) []byte`
- `func (s *Symmetric) TryDecrypt(data []byte) []byte`

### 非对称加密 (Asymmetric)
- `func NewAsymmetric(algorithm AsymmetricAlgorithm, safePrivateKeyBuf, safePublicKeyBuf *safe.SafeBuf) (*Asymmetric, error)`
- `func NewAsymmetricAndEraseKey(algorithm AsymmetricAlgorithm, privateKey, publicKey []byte) (*Asymmetric, error)`
- `func NewAsymmetricWithoutEraseKey(algorithm AsymmetricAlgorithm, privateKey, publicKey []byte, fastMode bool) (*Asymmetric, error)`
- `func NewRSA(priv, pub *safe.SafeBuf) (*Asymmetric, error)` / `NewRSAndEraseKey(...)` / `NewRSAWithOutEraseKey(...)`
- `func NewECDSA(priv, pub *safe.SafeBuf) (*Asymmetric, error)` / `NewECDSAndEraseKey(...)` / `NewECDSAWithOutEraseKey(...)`
- `func NewED25519(priv, pub *safe.SafeBuf) (*Asymmetric, error)` / `NewED25519AndEraseKey(...)` / `NewED25519WithOutEraseKey(...)`
- `func NewX25519(priv, pub *safe.SafeBuf) (*Asymmetric, error)` / `NewX25519AndEraseKey(...)` / `NewX25519WithOutEraseKey(...)`
- `func (a *Asymmetric) Close()`
- `func (a *Asymmetric) Sign(data []byte, hash ...crypto.Hash) ([]byte, error)`
- `func (a *Asymmetric) SignAndErase(data []byte, hash ...crypto.Hash) ([]byte, error)`
- `func (a *Asymmetric) MustSign(data []byte, hash ...crypto.Hash) []byte`
- `func (a *Asymmetric) Verify(data []byte, signature []byte, hash ...crypto.Hash) (bool, error)`
- `func (a *Asymmetric) MustVerify(data []byte, signature []byte, hash ...crypto.Hash) bool`
- `func (a *Asymmetric) Encrypt(safeBuf *safe.SafeBuf) ([]byte, error)`
- `func (a *Asymmetric) EncryptAndErase(data []byte) ([]byte, error)`
- `func (a *Asymmetric) EncryptBytes(data []byte) ([]byte, error)`
- `func (a *Asymmetric) MustEncrypt(data []byte) []byte`
- `func (a *Asymmetric) Decrypt(data []byte) (*safe.SafeBuf, error)`
- `func (a *Asymmetric) DecryptBytes(data []byte) ([]byte, error)`
- `func (a *Asymmetric) MustDecrypt(data []byte) []byte`
- `func (a *Asymmetric) TryDecrypt(data []byte) []byte`

### 密钥对生成
- `func GenerateRSAKeyPair(bitSize int) (priv, pub []byte, err error)`
- `func GenerateECDSAKeyPair(bitSize int) (priv, pub []byte, err error)`
- `func GenerateEd25519KeyPair() (priv, pub []byte, err error)`
- `func GenerateX25519KeyPair() (priv, pub []byte, err error)`

### Hash 与填充辅助
- `func MD5(data ...[]byte) []byte` / `MD5ToHex(data) string` / `MD5ToBase64(data) string` / `MD5ToUrlBase64(data) string`
- `func Sha256(data ...[]byte) []byte` / `Sha256ToHex(data) string` / `Sha256ToBase64(data) string` / `Sha256ToUrlBase64(data) string`
- `func Sha512(data ...[]byte) []byte` / `Sha512ToHex(data) string` / `Sha512ToBase64(data) string` / `Sha512ToUrlBase64(data) string`
- `func HmacSha256(key []byte, data ...[]byte) []byte`
- `func Pkcs5Padding(data []byte, blockSize int) []byte` / `Pkcs5UnPadding(data []byte) []byte`
- `func AnsiX923Padding(data []byte, blockSize int) []byte` / `AnsiX923UnPadding(data []byte) []byte`

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

*   **✅ 高并发签名 (FastMode)**:
    ```go
    // S端场景使用 FastMode
    a, _ := crypto.NewAsymmetricWithoutEraseKey(algo, priv, pub, true)
    defer a.Close()
    sig := a.MustSign(data)
    ```

