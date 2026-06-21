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
		"SHA1":              SHA1,
		"SHA1ToHex":         SHA1ToHex,
		"SHA1ToBase64":      SHA1ToBase64,
		"SHA1ToURLBase64":   SHA1ToURLBase64,
		"SHA256":            SHA256,
		"SHA256ToHex":       SHA256ToHex,
		"SHA256ToBase64":    SHA256ToBase64,
		"SHA256ToURLBase64": SHA256ToURLBase64,
		"SHA512":            SHA512,
		"SHA512ToHex":       SHA512ToHex,
		"SHA512ToBase64":    SHA512ToBase64,
		"SHA512ToURLBase64": SHA512ToURLBase64,

		// HMAC
		"HMACMD5":    HMACMD5,
		"HMACSHA1":   HMACSHA1,
		"HMACSHA256": HMACSHA256,
		"HMACSHA512": HMACSHA512,

		// Token
		"MakeToken": MakeToken,

		// AES GCM (Stateless)
		"Encrypt": jsEncrypt,
		"Decrypt": jsDecrypt,

		// AES CBC (Stateless)
		"EncryptCBC": jsEncryptCBC,
		"DecryptCBC": jsDecryptCBC,

		// RSA (Stateless)
		"RSAEncrypt": jsRSAEncrypt,
		"RSADecrypt": jsRSADecrypt,
		"RSASign":    jsRSASign,
		"RSAVerify":  jsRSAVerify,

		// Key Generation
		"GenerateRSAKeyPair":     jsGenerateRSAKeyPair,
		"GenerateECDSAKeyPair":   jsGenerateECDSAKeyPair,
		"GenerateEd25519KeyPair": jsGenerateEd25519KeyPair,
		"GenerateX25519KeyPair":  jsGenerateX25519KeyPair,
		"DeriveKey":              DeriveKey,
	})
}

func jsEncrypt(data, key, iv []byte) ([]byte, error) {
	s, err := NewAESGCMAndEraseKey(key, iv)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	res, err := s.EncryptBytes(data)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	return res, nil
}

func jsDecrypt(data, key, iv []byte) ([]byte, error) {
	s, err := NewAESGCMAndEraseKey(key, iv)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	res, err := s.DecryptBytes(data)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	return res, nil
}

func jsEncryptCBC(data, key, iv []byte) ([]byte, error) {
	s, err := NewAESCBCAndEraseKey(key, iv)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	res, err := s.EncryptBytes(data)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	return res, nil
}

func jsDecryptCBC(data, key, iv []byte) ([]byte, error) {
	s, err := NewAESCBCAndEraseKey(key, iv)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	res, err := s.DecryptBytes(data)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	return res, nil
}

func jsRSAEncrypt(data, pubKey []byte) ([]byte, error) {
	a, err := NewRSAAndEraseKey(nil, pubKey)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	res, err := a.EncryptBytes(data)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	return res, nil
}

func jsRSADecrypt(data, privKey []byte) ([]byte, error) {
	a, err := NewRSAAndEraseKey(privKey, nil)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	res, err := a.DecryptBytes(data)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	return res, nil
}

func jsRSASign(data, privKey []byte) ([]byte, error) {
	a, err := NewRSAAndEraseKey(privKey, nil)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	res, err := a.Sign(data)
	if err != nil {
		return nil, jsmod.MakeError(err)
	}
	return res, nil
}

func jsRSAVerify(data, sig, pubKey []byte) (bool, error) {
	a, err := NewRSAAndEraseKey(nil, pubKey)
	if err != nil {
		return false, jsmod.MakeError(err)
	}
	res, err := a.Verify(data, sig)
	if err != nil {
		return false, jsmod.MakeError(err)
	}
	return res, nil
}

func jsGenerateRSAKeyPair(bitSize int) ([]byte, []byte, error) {
	priv, pub, err := GenerateRSAKeyPair(bitSize)
	if err != nil {
		return nil, nil, jsmod.MakeError(err)
	}
	return priv, pub, nil
}

func jsGenerateECDSAKeyPair(bitSize int) ([]byte, []byte, error) {
	priv, pub, err := GenerateECDSAKeyPair(bitSize)
	if err != nil {
		return nil, nil, jsmod.MakeError(err)
	}
	return priv, pub, nil
}

func jsGenerateEd25519KeyPair() ([]byte, []byte, error) {
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		return nil, nil, jsmod.MakeError(err)
	}
	return priv, pub, nil
}

func jsGenerateX25519KeyPair() ([]byte, []byte, error) {
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, jsmod.MakeError(err)
	}
	return priv, pub, nil
}
