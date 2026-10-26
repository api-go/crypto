package crypto

import (
	"bytes"
	"crypto"
	"errors"
)

// SymmetricCipher 对称加密算法引擎接口
type SymmetricCipher interface {
	Encrypt(data []byte, key []byte, iv []byte) ([]byte, error)
	Decrypt(data []byte, key []byte, iv []byte) ([]byte, error)
}

// AutoIVCipher is an optional authenticated cipher capability. Implementations
// return ErrNotImplemented for modes that cannot safely identify both formats.
// DecryptCompatible must authenticate either the embedded IV format or legacy data.
type AutoIVCipher interface {
	EncryptAutoIV(data, key []byte) ([]byte, error)
	DecryptCompatible(data, key, legacyIV []byte) ([]byte, error)
}

// AsymmetricAlgorithm 非对称算法基础接口 (签名/验签)
type AsymmetricAlgorithm interface {
	ParsePrivateKey(der []byte) (any, error)
	ParsePublicKey(der []byte) (any, error)
	Sign(privateKey any, data []byte, hash ...crypto.Hash) ([]byte, error)
	Verify(publicKey any, data []byte, signature []byte, hash ...crypto.Hash) (bool, error)
}

// AsymmetricCipherAlgorithm 非对称加解密能力接口
type AsymmetricCipherAlgorithm interface {
	Encrypt(publicKey any, data []byte) ([]byte, error)
	Decrypt(privateKey any, data []byte) ([]byte, error)
}

// 通用错误
var (
	ErrKeySize            = errors.New("invalid key size")
	ErrNotImplemented     = errors.New("algorithm not implemented")
	ErrAlgorithmNoEncrypt = errors.New("the current algorithm does not support encryption")
	ErrAlgorithmNoDecrypt = errors.New("the current algorithm does not support decryption")
	ErrPrivKeyMissing     = errors.New("private key is not set")
	ErrPubKeyMissing      = errors.New("public key is not set")
)

// Pkcs5Padding 填充逻辑 (实际上是 PKCS#7，广泛兼容)
func Pkcs5Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// Pkcs5UnPadding 去除填充逻辑
func Pkcs5UnPadding(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return nil
	}
	unpadding := int(data[length-1])
	if unpadding > length || unpadding == 0 {
		return nil
	}
	return data[:length-unpadding]
}

// AnsiX923Padding 填充逻辑 (中间补 0，末尾补长度)
func AnsiX923Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	padtext[len(padtext)-1] = byte(padding) // 仅在末尾存长度
	return append(data, padtext...)
}

// AnsiX923UnPadding 去除 ANSI X9.23 填充
func AnsiX923UnPadding(data []byte) []byte {
	length := len(data)
	if length == 0 {
		return nil
	}
	unpadding := int(data[length-1])
	if unpadding > length || unpadding == 0 {
		return nil
	}
	return data[:length-unpadding]
}
