package crypto_test

import (
	"bytes"
	"testing"

	"apigo.cc/go/crypto"
)

func TestRSA_AllModes(t *testing.T) {
	priv, pub, _ := crypto.GenerateRSAKeyPair(2048)
	data := []byte("rsa multi-mode test")

	// 1. PSS (Default)
	a, _ := crypto.NewRSAWithoutEraseKey(priv, pub)
	sig, _ := a.Sign(data)
	if ok, _ := a.Verify(data, sig); !ok {
		t.Error("RSA PSS Sign failed")
	}
	enc, _ := a.EncryptBytes(data)
	dec, _ := a.DecryptBytes(enc)
	if !bytes.Equal(data, dec) {
		t.Error("RSA OAEP Encrypt failed")
	}

	// 2. FastMode
	fastA, _ := crypto.NewAsymmetricWithoutEraseKey(&crypto.RSAAlgorithm{IsPSS: true, IsOAEP: true}, priv, pub, true)
	sig2, _ := fastA.Sign(data)
	if ok, _ := fastA.Verify(data, sig2); !ok {
		t.Error("RSA FastMode failed")
	}
}

func TestECDSA_Hybrid(t *testing.T) {
	priv, pub, _ := crypto.GenerateECDSAKeyPair(256)
	data := []byte("ecdsa hybrid test")

	a, _ := crypto.NewECDSAAndEraseKey(append([]byte(nil), priv...), append([]byte(nil), pub...))

	// Test Hybrid Encrypt (ECDH + AESGCM)
	enc, err := a.EncryptBytes(data)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := a.DecryptBytes(enc)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, dec) {
		t.Error("ECDSA Hybrid roundtrip failed")
	}
}

func TestEd25519_Simple(t *testing.T) {
	priv, pub, _ := crypto.GenerateEd25519KeyPair()
	data := []byte("ed25519 sign test")

	a, _ := crypto.NewED25519AndEraseKey(priv, pub)
	sig, _ := a.Sign(data)
	if ok, _ := a.Verify(data, sig); !ok {
		t.Error("Ed25519 failed")
	}

	// Test Negative: Algorithm doesn't support encryption
	if _, err := a.EncryptBytes(data); err == nil {
		t.Error("Ed25519 should NOT support encryption")
	}
}

func TestX25519_Hybrid(t *testing.T) {
	priv, pub, _ := crypto.GenerateX25519KeyPair()
	data := []byte("x25519 data")

	a, _ := crypto.NewX25519WithoutEraseKey(priv, pub)
	enc, _ := a.EncryptBytes(data)
	dec, _ := a.DecryptBytes(enc)
	if !bytes.Equal(data, dec) {
		t.Error("X25519 roundtrip failed")
	}
}

func TestAsymmetricErrors(t *testing.T) {
	_, pub, _ := crypto.GenerateRSAKeyPair(2048)

	// Only public key
	a, _ := crypto.NewRSAWithoutEraseKey(nil, pub)
	if _, err := a.Sign([]byte("x")); err == nil {
		t.Error("Should fail to sign without private key")
	}

	// Missing both
	aEmpty, _ := crypto.NewRSAWithoutEraseKey(nil, nil)
	if _, err := aEmpty.EncryptBytes([]byte("x")); err == nil {
		t.Error("Should fail to encrypt without public key")
	}
}
