package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"apigo.cc/go/safe"
)

type RSAAlgorithm struct {
	IsPSS  bool
	IsOAEP bool
	Hash   crypto.Hash
}

var (
	RSA = &RSAAlgorithm{IsPSS: true, IsOAEP: true, Hash: crypto.SHA256}
	// Deprecated: RSAPKCS1v15 is not recommended.
	RSAPKCS1v15 = &RSAAlgorithm{IsPSS: false, IsOAEP: false, Hash: crypto.SHA256}
)

func NewRSA(safePrivateKeyBuf, safePublicKeyBuf *safe.SafeBuf) (*Asymmetric, error) {
	return NewAsymmetric(RSA, safePrivateKeyBuf, safePublicKeyBuf)
}
func NewRSAndEraseKey(safePrivateKeyBuf, safePublicKeyBuf []byte) (*Asymmetric, error) {
	return NewAsymmetricAndEraseKey(RSA, safePrivateKeyBuf, safePublicKeyBuf)
}
func NewRSAWithOutEraseKey(safePrivateKeyBuf, safePublicKeyBuf []byte) (*Asymmetric, error) {
	return NewAsymmetricWithoutEraseKey(RSA, safePrivateKeyBuf, safePublicKeyBuf, false)
}

func GenerateRSAKeyPair(bitSize int) ([]byte, []byte, error) {
	if bitSize < 2048 {
		bitSize = 2048
	}
	priKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(priKey)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&priKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func (r *RSAAlgorithm) ParsePrivateKey(der []byte) (any, error) {
	keyAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		keyAny, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, err
		}
	}
	privKey, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return privKey, nil
}

func (r *RSAAlgorithm) ParsePublicKey(der []byte) (any, error) {
	pubKeyAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pubKeyAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return pubKey, nil
}

func (r *RSAAlgorithm) Sign(privateKeyObj any, data []byte, hash ...crypto.Hash) ([]byte, error) {
	privKey, ok := privateKeyObj.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type for RSA")
	}
	hFunc := r.Hash
	if len(hash) > 0 {
		hFunc = hash[0]
	}
	if hFunc == 0 {
		hFunc = crypto.SHA256
	}
	hasher := hFunc.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)
	if r.IsPSS {
		return rsa.SignPSS(rand.Reader, privKey, hFunc, hashed, nil)
	}
	return rsa.SignPKCS1v15(rand.Reader, privKey, hFunc, hashed)
}

func (r *RSAAlgorithm) Verify(publicKeyObj any, data []byte, signature []byte, hash ...crypto.Hash) (bool, error) {
	pubKey, ok := publicKeyObj.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("invalid public key type for RSA")
	}
	hFunc := r.Hash
	if len(hash) > 0 {
		hFunc = hash[0]
	}
	if hFunc == 0 {
		hFunc = crypto.SHA256
	}
	hasher := hFunc.New()
	hasher.Write(data)
	hashed := hasher.Sum(nil)
	var err error
	if r.IsPSS {
		err = rsa.VerifyPSS(pubKey, hFunc, hashed, signature, nil)
	} else {
		err = rsa.VerifyPKCS1v15(pubKey, hFunc, hashed, signature)
	}
	return err == nil, nil
}

func (r *RSAAlgorithm) Encrypt(publicKeyObj any, data []byte) ([]byte, error) {
	pubKey, ok := publicKeyObj.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type for RSA")
	}
	if r.IsOAEP {
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data, nil)
	}
	return rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
}

func (r *RSAAlgorithm) Decrypt(privateKeyObj any, data []byte) ([]byte, error) {
	privKey, ok := privateKeyObj.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type for RSA")
	}
	if r.IsOAEP {
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, data, nil)
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privKey, data)
}
