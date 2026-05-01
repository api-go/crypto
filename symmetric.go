package crypto

import (
	"errors"
	"runtime"

	"apigo.cc/go/safe"
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

// MustEncrypt 加密失败时返回空字节切片 (静默加密)
func (s *Symmetric) MustEncrypt(data []byte) []byte {
	r, err := s.EncryptBytes(data)
	if err != nil {
		return []byte{}
	}
	return r
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
	iv := s.iv.Open()
	defer iv.Close()
	return s.cipher.Decrypt(data, key.Data, iv.Data)
}

// MustDecryptBytes 解密失败时返回空字节切片 (静默解密)
func (s *Symmetric) MustDecrypt(data []byte) []byte {
	r, err := s.DecryptBytes(data)
	if err != nil {
		return []byte{}
	}
	return r
}

// TryDecryptBytes 解密失败时返回原始数据 (静默解密)
func (s *Symmetric) TryDecrypt(data []byte) []byte {
	r, err := s.DecryptBytes(data)
	if err != nil {
		return data
	}
	return r
}
