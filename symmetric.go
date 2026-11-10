package crypto

import (
	"crypto/sha256"
	"errors"
	"io"
	"runtime"

	"github.com/api-go/safe"
	"golang.org/x/crypto/hkdf"
)

// Symmetric 封装对称加密的生命周期与安全存储
type Symmetric struct {
	cipher SymmetricCipher
	key    *safe.SafeBuf
	iv     *safe.SafeBuf
}

// NewSymmetric 基于已有的 SafeBuf 创建 Symmetric
func NewSymmetric(cipher SymmetricCipher, safeKeyBuf, safeIvBuf *safe.SafeBuf) (*Symmetric, error) {
	s := &Symmetric{cipher: cipher, key: safeKeyBuf, iv: safeIvBuf}
	runtime.SetFinalizer(s, func(obj *Symmetric) { obj.Close() })
	return s, nil
}

// NewSymmetricAndEraseKey 创建并自动擦除传入的密钥与 IV
func NewSymmetricAndEraseKey(cipher SymmetricCipher, key, iv []byte) (*Symmetric, error) {
	defer safe.ZeroMemory(key)
	defer safe.ZeroMemory(iv)
	return NewSymmetricWithoutEraseKey(cipher, key, iv)
}

// NewSymmetricWithoutEraseKey 创建但不擦除传入的密钥与 IV，支持密钥长度自动适配（混淆防御）
func NewSymmetricWithoutEraseKey(cipher SymmetricCipher, key, iv []byte) (*Symmetric, error) {
	keySize := 16
	if len(key) >= 32 {
		keySize = 32
	} else if len(key) >= 24 {
		keySize = 24
	} else if len(key) < 16 {
		return nil, errors.New("key size is too short, at least 16 bytes required")
	}

	// 自动适配长度，允许传入超长 buffer 以混淆特征
	s := &Symmetric{
		cipher: cipher,
		key:    safe.NewSafeBuf(key[:keySize]),
		iv:     safe.NewSafeBuf(iv),
	}
	runtime.SetFinalizer(s, func(obj *Symmetric) { obj.Close() })
	return s, nil
}

// Close 销毁加密实例并擦除密钥
func (s *Symmetric) Close() {
	if s.key != nil {
		s.key.Close()
	}
	if s.iv != nil {
		s.iv.Close()
	}
}

// DeriveKey derives a domain-separated subkey from the protected symmetric key.
// info is public context identifying the subkey's purpose and is not erased.
func (s *Symmetric) DeriveKey(info []byte, size int) (*safe.SafeBuf, error) {
	if s == nil || s.key == nil || s.iv == nil {
		return nil, errors.New("symmetric key is unavailable")
	}
	if size <= 0 || size > 255*sha256.Size {
		return nil, errors.New("derived key size must be between 1 and 8160 bytes")
	}
	key := s.key.Open()
	defer key.Close()
	salt := s.iv.Open()
	defer salt.Close()
	derived := make([]byte, size)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key.Data, salt.Data, info), derived); err != nil {
		safe.ZeroMemory(derived)
		return nil, err
	}
	return safe.NewSafeBufAndErase(derived), nil
}

// Encrypt 使用 SafeBuf 传入明文进行加密
func (s *Symmetric) Encrypt(safeBuf *safe.SafeBuf) ([]byte, error) {
	buf := safeBuf.Open()
	defer buf.Close()
	return s.EncryptBytes(buf.Data)
}

// EncryptAndErase 使用字节切片传入明文进行加密并自动擦除明文
func (s *Symmetric) EncryptAndErase(data []byte) ([]byte, error) {
	defer safe.ZeroMemory(data)
	return s.EncryptBytes(data)
}

// EncryptBytes 使用字节切片传入明文进行加密
func (s *Symmetric) EncryptBytes(data []byte) ([]byte, error) {
	key := s.key.Open()
	defer key.Close()
	iv := s.iv.Open()
	defer iv.Close()
	return s.cipher.Encrypt(data, key.Data, iv.Data)
}

// Decrypt 进行解密并返回一个受保护的 SafeBuf
func (s *Symmetric) Decrypt(data []byte) (*safe.SafeBuf, error) {
	buf, err := s.DecryptBytes(data)
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(buf)
	return safe.NewSafeBuf(buf), nil
}

// DecryptBytes 进行解密并返回原始明文字节
func (s *Symmetric) DecryptBytes(data []byte) ([]byte, error) {
	key := s.key.Open()
	defer key.Close()
	var legacyIV []byte
	if s.iv != nil {
		iv := s.iv.Open()
		defer iv.Close()
		legacyIV = iv.Data
	}
	if cipher, ok := s.cipher.(AutoIVCipher); ok {
		return cipher.DecryptCompatible(data, key.Data, legacyIV)
	}
	return s.cipher.Decrypt(data, key.Data, legacyIV)
}

// TryDecrypt 解密失败时返回原始数据 (静默解密)
func (s *Symmetric) TryDecrypt(data []byte) []byte {
	r, err := s.DecryptBytes(data)
	if err != nil {
		return data
	}
	return r
}

// EncryptAutoIV encrypts protected plaintext with a fresh embedded IV.
// Prefer this to fixed-IV encryption for new data. Unsupported ciphers return
// ErrNotImplemented; no fallback to fixed-IV encryption is performed.
func (s *Symmetric) EncryptAutoIV(data *safe.SafeBuf) ([]byte, error) {
	plain := data.Open()
	defer plain.Close()
	return s.EncryptBytesAutoIV(plain.Data)
}

// EncryptBytesAutoIV encrypts with a fresh embedded IV, without modifying the
// configured legacy IV. It is safe for concurrent calls without Close.
func (s *Symmetric) EncryptBytesAutoIV(data []byte) ([]byte, error) {
	cipher, ok := s.cipher.(AutoIVCipher)
	if !ok {
		return nil, ErrNotImplemented
	}
	key := s.key.Open()
	defer key.Close()
	return cipher.EncryptAutoIV(data, key.Data)
}

// EncryptAndEraseAutoIV encrypts with a fresh embedded IV and erases plaintext,
// including on failure.
func (s *Symmetric) EncryptAndEraseAutoIV(data []byte) ([]byte, error) {
	defer safe.ZeroMemory(data)
	return s.EncryptBytesAutoIV(data)
}
