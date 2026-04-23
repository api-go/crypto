package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"apigo.cc/go/safe"
)

type Ed25519Algorithm struct{}

var ED25519 = &Ed25519Algorithm{}

func NewED25519(safePrivateKeyBuf, safePublicKeyBuf *safe.SafeBuf) (*Asymmetric, error) {
	return NewAsymmetric(ED25519, safePrivateKeyBuf, safePublicKeyBuf)
}
func NewED25519AndEraseKey(safePrivateKeyBuf, safePublicKeyBuf []byte) (*Asymmetric, error) {
	return NewAsymmetricAndEraseKey(ED25519, safePrivateKeyBuf, safePublicKeyBuf)
}
func NewED25519WithOutEraseKey(safePrivateKeyBuf, safePublicKeyBuf []byte) (*Asymmetric, error) {
	return NewAsymmetricWithoutEraseKey(ED25519, safePrivateKeyBuf, safePublicKeyBuf, false)
}

func GenerateEd25519KeyPair() ([]byte, []byte, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKey, nil
}

func (e *Ed25519Algorithm) ParsePrivateKey(der []byte) (any, error) {
	if len(der) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key size")
	}
	return ed25519.PrivateKey(der), nil
}

func (e *Ed25519Algorithm) ParsePublicKey(der []byte) (any, error) {
	if len(der) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key size")
	}
	return ed25519.PublicKey(der), nil
}

func (e *Ed25519Algorithm) Sign(privateKeyObj any, data []byte, hash ...crypto.Hash) ([]byte, error) {
	privKey, ok := privateKeyObj.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type for Ed25519")
	}
	return ed25519.Sign(privKey, data), nil
}

func (e *Ed25519Algorithm) Verify(publicKeyObj any, data []byte, signature []byte, hash ...crypto.Hash) (bool, error) {
	pubKey, ok := publicKeyObj.(ed25519.PublicKey)
	if !ok {
		return false, errors.New("invalid public key type for Ed25519")
	}
	return ed25519.Verify(pubKey, data, signature), nil
}
