package crypto

import (
	"apigo.cc/go/jsmod"
)

func init() {
	jsmod.Register("crypto", map[string]any{
		// Hash
		"md5":               MD5,
		"md5ToHex":          MD5ToHex,
		"md5ToBase64":       MD5ToBase64,
		"md5ToUrlBase64":    MD5ToUrlBase64,
		"sha1":              Sha1,
		"sha1ToHex":         Sha1ToHex,
		"sha1ToBase64":      Sha1ToBase64,
		"sha1ToUrlBase64":   Sha1ToUrlBase64,
		"sha256":            Sha256,
		"sha256ToHex":       Sha256ToHex,
		"sha256ToBase64":    Sha256ToBase64,
		"sha256ToUrlBase64": Sha256ToUrlBase64,
		"sha512":            Sha512,
		"sha512ToHex":       Sha512ToHex,
		"sha512ToBase64":    Sha512ToBase64,
		"sha512ToUrlBase64": Sha512ToUrlBase64,

		// HMAC
		"hmacMd5":    HmacMD5,
		"hmacSha1":   HmacSha1,
		"hmacSha256": HmacSha256,
		"hmacSha512": HmacSha512,

		// Token
		"makeToken": MakeToken,

		// AES GCM (Stateless)
		"encrypt": func(data, key, iv []byte) ([]byte, error) {
			s, err := NewAESGCMAndEraseKey(key, iv)
			if err != nil {
				return nil, err
			}
			return s.EncryptBytes(data)
		},
		"decrypt": func(data, key, iv []byte) ([]byte, error) {
			s, err := NewAESGCMAndEraseKey(key, iv)
			if err != nil {
				return nil, err
			}
			return s.DecryptBytes(data)
		},

		// AES CBC (Stateless)
		"encryptCBC": func(data, key, iv []byte) ([]byte, error) {
			s, err := NewAESCBCAndEraseKey(key, iv)
			if err != nil {
				return nil, err
			}
			return s.EncryptBytes(data)
		},
		"decryptCBC": func(data, key, iv []byte) ([]byte, error) {
			s, err := NewAESCBCAndEraseKey(key, iv)
			if err != nil {
				return nil, err
			}
			return s.DecryptBytes(data)
		},

		// RSA (Stateless)
		"rsaEncrypt": func(data, pubKey []byte) ([]byte, error) {
			a, err := NewRSAAndEraseKey(nil, pubKey)
			if err != nil {
				return nil, err
			}
			return a.EncryptBytes(data)
		},
		"rsaDecrypt": func(data, privKey []byte) ([]byte, error) {
			a, err := NewRSAAndEraseKey(privKey, nil)
			if err != nil {
				return nil, err
			}
			return a.DecryptBytes(data)
		},
		"rsaSign": func(data, privKey []byte) ([]byte, error) {
			a, err := NewRSAAndEraseKey(privKey, nil)
			if err != nil {
				return nil, err
			}
			return a.Sign(data)
		},
		"rsaVerify": func(data, sig, pubKey []byte) (bool, error) {
			a, err := NewRSAAndEraseKey(nil, pubKey)
			if err != nil {
				return false, err
			}
			return a.Verify(data, sig)
		},

		// Key Generation
		"generateRSAKeyPair":     GenerateRSAKeyPair,
		"generateECDSAKeyPair":   GenerateECDSAKeyPair,
		"generateEd25519KeyPair": GenerateEd25519KeyPair,
		"generateX25519KeyPair":  GenerateX25519KeyPair,
		"deriveKey":              DeriveKey,
	})
}
