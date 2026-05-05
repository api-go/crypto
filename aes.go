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
