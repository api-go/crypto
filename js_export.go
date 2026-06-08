package crypto

import (
	"apigo.cc/go/jsmod"
)

func init() {
	jsmod.Register("crypto", map[string]any{
		// Hash
		"MD5":               MD5,
		"MD5ToHex":          MD5ToHex,
		"MD5ToBase64":       MD5ToBase64,
		"MD5ToURLBase64":    MD5ToURLBase64,
		"Sha1":              Sha1,
		"Sha1ToHex":         Sha1ToHex,
		"Sha1ToBase64":      Sha1ToBase64,
		"Sha1ToURLBase64":   Sha1ToURLBase64,
		"Sha256":            Sha256,
		"Sha256ToHex":       Sha256ToHex,
		"Sha256ToBase64":    Sha256ToBase64,
		"Sha256ToURLBase64": Sha256ToURLBase64,
		"Sha512":            Sha512,
		"Sha512ToHex":       Sha512ToHex,
		"Sha512ToBase64":    Sha512ToBase64,
		"Sha512ToURLBase64": Sha512ToURLBase64,

		// HMAC
		"HMACMD5":    HMACMD5,
		"HMACSha1":   HMACSha1,
		"HMACSha256": HMACSha256,
		"HMACSha512": HMACSha512,

		// Token
		"MakeToken": MakeToken,

		// AES GCM (Stateless)
		"Encrypt": func(data, key, iv []byte) ([]byte, error) {
			s, err := NewAESGCMAndEraseKey(key, iv)
			if err != nil {
				return nil, err
			}
			return s.EncryptBytes(data)
		},
		"Decrypt": func(data, key, iv []byte) ([]byte, error) {
			s, err := NewAESGCMAndEraseKey(key, iv)
			if err != nil {
				return nil, err
			}
			return s.DecryptBytes(data)
		},

		// AES CBC (Stateless)
		"EncryptCBC": func(data, key, iv []byte) ([]byte, error) {
			s, err := NewAESCBCAndEraseKey(key, iv)
			if err != nil {
				return nil, err
			}
			return s.EncryptBytes(data)
		},
		"DecryptCBC": func(data, key, iv []byte) ([]byte, error) {
			s, err := NewAESCBCAndEraseKey(key, iv)
			if err != nil {
				return nil, err
			}
			return s.DecryptBytes(data)
		},

		// RSA (Stateless)
		"RSAEncrypt": func(data, pubKey []byte) ([]byte, error) {
			a, err := NewRSAAndEraseKey(nil, pubKey)
			if err != nil {
				return nil, err
			}
			return a.EncryptBytes(data)
		},
		"RSADecrypt": func(data, privKey []byte) ([]byte, error) {
			a, err := NewRSAAndEraseKey(privKey, nil)
			if err != nil {
				return nil, err
			}
			return a.DecryptBytes(data)
		},
		"RSASign": func(data, privKey []byte) ([]byte, error) {
			a, err := NewRSAAndEraseKey(privKey, nil)
			if err != nil {
				return nil, err
			}
			return a.Sign(data)
		},
		"RSAVerify": func(data, sig, pubKey []byte) (bool, error) {
			a, err := NewRSAAndEraseKey(nil, pubKey)
			if err != nil {
				return false, err
			}
			return a.Verify(data, sig)
		},

		// Key Generation
		"GenerateRSAKeyPair":     GenerateRSAKeyPair,
		"GenerateECDSAKeyPair":   GenerateECDSAKeyPair,
		"GenerateEd25519KeyPair": GenerateEd25519KeyPair,
		"GenerateX25519KeyPair":  GenerateX25519KeyPair,
		"DeriveKey":              DeriveKey,
	})
}
