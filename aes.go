package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"apigo.cc/go/safe"
)

type AESCipher struct{ useGCM bool }

var (
	AESCBC = &AESCipher{useGCM: false}
	AESGCM = &AESCipher{useGCM: true}
)

func NewAESCBC(safeKeyBuf, safeIvBuf *safe.SafeBuf) (*Symmetric, error) {
	return NewSymmetric(AESCBC, safeKeyBuf, safeIvBuf)
}

func NewAESCBCAndEraseKey(key, iv []byte) (*Symmetric, error) {
	return NewSymmetricAndEraseKey(AESCBC, key, iv)
}

func NewAESCBCWithoutEraseKey(key, iv []byte) (*Symmetric, error) {
	return NewSymmetricWithoutEraseKey(AESCBC, key, iv)
}

func NewAESGCM(safeKeyBuf, safeIvBuf *safe.SafeBuf) (*Symmetric, error) {
	return NewSymmetric(AESGCM, safeKeyBuf, safeIvBuf)
}

func NewAESGCMAndEraseKey(key, iv []byte) (*Symmetric, error) {
	return NewSymmetricAndEraseKey(AESGCM, key, iv)
}

func NewAESGCMWithoutEraseKey(key, iv []byte) (*Symmetric, error) {
	return NewSymmetricWithoutEraseKey(AESGCM, key, iv)
}

func NewAESCBCByPassword(password, salt []byte) (*Symmetric, error) {
	derived := DeriveKey(password, salt, 32+16)
	defer safe.ZeroMemory(derived)
	return NewSymmetricAndEraseKey(AESCBC, derived[:32], derived[32:])
}

func NewAESGCMByPassword(password, salt []byte) (*Symmetric, error) {
	derived := DeriveKey(password, salt, 32+12)
	defer safe.ZeroMemory(derived)
	return NewSymmetricAndEraseKey(AESGCM, derived[:32], derived[32:])
}

func (c *AESCipher) Encrypt(data []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if c.useGCM {
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if len(iv) < aesgcm.NonceSize() {
			return nil, errors.New("GCM IV must contain at least 12 bytes")
		}
		return aesgcm.Seal(nil, iv[:aesgcm.NonceSize()], data, nil), nil
	}
	blockSize := block.BlockSize()
	paddingData := Pkcs5Padding(data, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	crypted := make([]byte, len(paddingData))
	blockMode.CryptBlocks(crypted, paddingData)
	return crypted, nil
}

func (c *AESCipher) Decrypt(data []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if c.useGCM {
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if len(iv) < aesgcm.NonceSize() {
			return nil, errors.New("GCM IV must contain at least 12 bytes")
		}
		return aesgcm.Open(nil, iv[:aesgcm.NonceSize()], data, nil)
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:block.BlockSize()])
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	origData := make([]byte, len(data))
	blockMode.CryptBlocks(origData, data)
	return Pkcs5UnPadding(origData), nil
}

// EncryptAutoIV returns nonce || ciphertext || tag (12-byte nonce, 16-byte tag).
// A key must not encrypt more than 2^32 messages using random nonces.
func (c *AESCipher) EncryptAutoIV(data, key []byte) ([]byte, error) {
	if !c.useGCM {
		return nil, ErrNotImplemented
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nil, data, nil), nil
}

// DecryptCompatible authenticates the embedded-nonce format first, then legacy
// ciphertext using legacyIV. Explicit Decrypt retains its original wire contract.
func (c *AESCipher) DecryptCompatible(data, key, legacyIV []byte) ([]byte, error) {
	if !c.useGCM {
		return c.Decrypt(data, key, legacyIV)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(data) >= gcm.NonceSize()+gcm.Overhead() {
		plain, openErr := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
		if openErr == nil {
			return plain, nil
		}
	}
	if len(legacyIV) >= gcm.NonceSize() {
		return gcm.Open(nil, legacyIV[:gcm.NonceSize()], data, nil)
	}
	return nil, errors.New("GCM authentication failed")
}
