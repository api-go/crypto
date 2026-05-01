package crypto

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"

	"apigo.cc/go/safe"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type X25519Algorithm struct {
	UseGCM  bool
	KdfInfo []byte
	KdfSalt []byte
	Hash    crypto.Hash
}

var (
	X25519GCM = &X25519Algorithm{UseGCM: true, Hash: crypto.SHA256}
	X25519CBC = &X25519Algorithm{UseGCM: false, Hash: crypto.SHA256}
)

func NewX25519(safePrivateKeyBuf, safePublicKeyBuf *safe.SafeBuf) (*Asymmetric, error) {
	return NewAsymmetric(X25519GCM, safePrivateKeyBuf, safePublicKeyBuf)
}
func NewX25519AndEraseKey(safePrivateKeyBuf, safePublicKeyBuf []byte) (*Asymmetric, error) {
	return NewAsymmetricAndEraseKey(X25519GCM, safePrivateKeyBuf, safePublicKeyBuf)
}
func NewX25519WithoutEraseKey(safePrivateKeyBuf, safePublicKeyBuf []byte) (*Asymmetric, error) {
	return NewAsymmetricWithoutEraseKey(X25519GCM, safePrivateKeyBuf, safePublicKeyBuf, false)
}

func NewX25519Algorithm(useGCM bool, hash crypto.Hash, kdfInfo, kdfSalt []byte) *X25519Algorithm {
	return &X25519Algorithm{UseGCM: useGCM, Hash: hash, KdfInfo: kdfInfo, KdfSalt: kdfSalt}
}

func GenerateX25519KeyPair() ([]byte, []byte, error) {
	privKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privKey); err != nil {
		return nil, nil, err
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

func (x *X25519Algorithm) ParsePrivateKey(der []byte) (any, error) {
	if len(der) != curve25519.ScalarSize {
		return nil, errors.New("invalid X25519 private key size")
	}
	key := make([]byte, curve25519.ScalarSize)
	copy(key, der)
	return key, nil
}

func (x *X25519Algorithm) ParsePublicKey(der []byte) (any, error) {
	if len(der) != curve25519.PointSize {
		return nil, errors.New("invalid X25519 public key size")
	}
	key := make([]byte, curve25519.PointSize)
	copy(key, der)
	return key, nil
}

func (x *X25519Algorithm) Sign(privateKeyObj any, data []byte, hash ...crypto.Hash) ([]byte, error) {
	return nil, errors.New("X25519 does not support signing, use Ed25519 instead")
}

func (x *X25519Algorithm) Verify(publicKeyObj any, data []byte, signature []byte, hash ...crypto.Hash) (bool, error) {
	return false, errors.New("X25519 does not support verification, use Ed25519 instead")
}

func (x *X25519Algorithm) Encrypt(publicKeyObj any, data []byte) ([]byte, error) {
	targetPub, ok := publicKeyObj.([]byte)
	if !ok || len(targetPub) != curve25519.PointSize {
		return nil, errors.New("invalid public key type/size for X25519")
	}
	ephemeralPriv, ephemeralPub, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(ephemeralPriv)
	sharedSecret, err := curve25519.X25519(ephemeralPriv, targetPub)
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(sharedSecret)
	hFunc := x.Hash
	if hFunc == 0 {
		hFunc = crypto.SHA256
	}
	hkdfReader := hkdf.New(hFunc.New, sharedSecret, x.KdfSalt, x.KdfInfo)
	aesKey := make([]byte, 32)
	defer safe.ZeroMemory(aesKey)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, err
	}
	cipherAlgo := &AESCipher{useGCM: x.UseGCM}
	ivLen := 16
	if x.UseGCM {
		ivLen = 12
	}
	iv := safe.MakeSafeToken(ivLen)
	cipherText, err := cipherAlgo.Encrypt(data, aesKey, iv)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(ephemeralPub)+len(iv)+len(cipherText))
	out = append(out, ephemeralPub...)
	out = append(out, iv...)
	out = append(out, cipherText...)
	return out, nil
}

func (x *X25519Algorithm) Decrypt(privateKeyObj any, data []byte) ([]byte, error) {
	myPriv, ok := privateKeyObj.([]byte)
	if !ok || len(myPriv) != curve25519.ScalarSize {
		return nil, errors.New("invalid private key type/size for X25519")
	}
	pubKeyLen := curve25519.PointSize
	ivLen := 16
	if x.UseGCM {
		ivLen = 12
	}
	if len(data) < pubKeyLen+ivLen {
		return nil, errors.New("invalid ciphertext package size")
	}
	ephemeralPub := data[:pubKeyLen]
	iv := data[pubKeyLen : pubKeyLen+ivLen]
	cipherText := data[pubKeyLen+ivLen:]
	sharedSecret, err := curve25519.X25519(myPriv, ephemeralPub)
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(sharedSecret)
	hFunc := x.Hash
	if hFunc == 0 {
		hFunc = crypto.SHA256
	}
	hkdfReader := hkdf.New(hFunc.New, sharedSecret, x.KdfSalt, x.KdfInfo)
	aesKey := make([]byte, 32)
	defer safe.ZeroMemory(aesKey)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, err
	}
	cipherAlgo := &AESCipher{useGCM: x.UseGCM}
	return cipherAlgo.Decrypt(cipherText, aesKey, iv)
}
