package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"

	"apigo.cc/go/safe"
	"golang.org/x/crypto/hkdf"
)

type ECDSAAlgorithm struct {
	UseGCM  bool
	KdfInfo []byte
	KdfSalt []byte
	Hash    crypto.Hash
}

var (
	ECDSAGCM = &ECDSAAlgorithm{UseGCM: true, Hash: crypto.SHA256}
	ECDSACBC = &ECDSAAlgorithm{UseGCM: false, Hash: crypto.SHA256}
)

func NewECDSA(safePrivateKeyBuf, safePublicKeyBuf *safe.SafeBuf) (*Asymmetric, error) {
	return NewAsymmetric(ECDSAGCM, safePrivateKeyBuf, safePublicKeyBuf)
}
func NewECDSAndEraseKey(safePrivateKeyBuf, safePublicKeyBuf []byte) (*Asymmetric, error) {
	return NewAsymmetricAndEraseKey(ECDSAGCM, safePrivateKeyBuf, safePublicKeyBuf)
}
func NewECDSAWithOutEraseKey(safePrivateKeyBuf, safePublicKeyBuf []byte) (*Asymmetric, error) {
	return NewAsymmetricWithoutEraseKey(ECDSAGCM, safePrivateKeyBuf, safePublicKeyBuf, false)
}

func NewECDSAAlgorithm(useGCM bool, hash crypto.Hash, kdfInfo, kdfSalt []byte) *ECDSAAlgorithm {
	return &ECDSAAlgorithm{UseGCM: useGCM, Hash: hash, KdfInfo: kdfInfo, KdfSalt: kdfSalt}
}

func GenerateECDSAKeyPair(bitSize int) ([]byte, []byte, error) {
	var curve elliptic.Curve
	switch bitSize {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	default:
		curve = elliptic.P521()
	}

	priKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := x509.MarshalECPrivateKey(priKey)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&priKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func (e *ECDSAAlgorithm) ParsePrivateKey(der []byte) (any, error) {
	return x509.ParseECPrivateKey(der)
}

func (e *ECDSAAlgorithm) ParsePublicKey(der []byte) (any, error) {
	pubKeyAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return pubKey, nil
}

func (e *ECDSAAlgorithm) Sign(privateKeyObj any, data []byte, hash ...crypto.Hash) ([]byte, error) {
	privKey, ok := privateKeyObj.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key")
	}
	hFunc := e.Hash
	if len(hash) > 0 {
		hFunc = hash[0]
	}
	if hFunc == 0 {
		hFunc = crypto.SHA256
	}
	hasher := hFunc.New()
	hasher.Write(data)
	return ecdsa.SignASN1(rand.Reader, privKey, hasher.Sum(nil))
}

func (e *ECDSAAlgorithm) Verify(publicKeyObj any, data []byte, signature []byte, hash ...crypto.Hash) (bool, error) {
	pubKey, ok := publicKeyObj.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("invalid public key")
	}
	hFunc := e.Hash
	if len(hash) > 0 {
		hFunc = hash[0]
	}
	if hFunc == 0 {
		hFunc = crypto.SHA256
	}
	hasher := hFunc.New()
	hasher.Write(data)
	return ecdsa.VerifyASN1(pubKey, hasher.Sum(nil), signature), nil
}

func (e *ECDSAAlgorithm) Encrypt(publicKeyObj any, data []byte) ([]byte, error) {
	ecdsaPub, ok := publicKeyObj.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key type for ECDSA")
	}
	ecdhPub, err := ecdsaPub.ECDH()
	if err != nil {
		return nil, err
	}
	ephemeralPriv, err := ecdhPub.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := ephemeralPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(sharedSecret)
	hkdfReader := hkdf.New(e.Hash.New, sharedSecret, e.KdfSalt, e.KdfInfo)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(aesKey)
	cipherAlgo := &AESCipher{useGCM: e.UseGCM}
	ivLen := 16
	if e.UseGCM {
		ivLen = 12
	}
	iv := safe.MakeSafeToken(ivLen)
	cipherText, err := cipherAlgo.Encrypt(data, aesKey, iv)
	if err != nil {
		return nil, err
	}
	pubBytes := ephemeralPriv.PublicKey().Bytes()
	out := make([]byte, 0, len(pubBytes)+len(iv)+len(cipherText))
	out = append(out, pubBytes...)
	out = append(out, iv...)
	out = append(out, cipherText...)
	return out, nil
}

func (e *ECDSAAlgorithm) Decrypt(privateKeyObj any, data []byte) ([]byte, error) {
	ecdsaPriv, ok := privateKeyObj.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type for ECDSA")
	}
	ecdhPriv, err := ecdsaPriv.ECDH()
	if err != nil {
		return nil, err
	}
	pubKeyLen := len(ecdhPriv.PublicKey().Bytes())
	ivLen := 16
	if e.UseGCM {
		ivLen = 12
	}
	if len(data) < pubKeyLen+ivLen {
		return nil, errors.New("invalid ciphertext package size")
	}
	ephemeralPubBytes := data[:pubKeyLen]
	iv := data[pubKeyLen : pubKeyLen+ivLen]
	cipherText := data[pubKeyLen+ivLen:]
	ephemeralPub, err := ecdhPriv.Curve().NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := ecdhPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(sharedSecret)
	hkdfReader := hkdf.New(e.Hash.New, sharedSecret, e.KdfSalt, e.KdfInfo)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, aesKey); err != nil {
		return nil, err
	}
	defer safe.ZeroMemory(aesKey)
	cipherAlgo := &AESCipher{useGCM: e.UseGCM}
	return cipherAlgo.Decrypt(cipherText, aesKey, iv)
}
