package crypto_test

import (
	"bytes"
	"testing"

	"apigo.cc/go/cast"
	"apigo.cc/go/crypto"
)

func TestMustAndTryMethods(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	data := []byte("hello world")

	s, _ := crypto.NewAESCBCAndEraseKey(key, iv)
	encS, _ := s.EncryptBytes(data)

	// Test with cast.As
	if !bytes.Equal(cast.As(s.EncryptBytes(data)), encS) {
		t.Error("EncryptBytes with cast.As mismatch")
	}

	if !bytes.Equal(cast.As(s.DecryptBytes(encS)), data) {
		t.Error("DecryptBytes with cast.As mismatch")
	}

	// Test TryDecrypt
	if !bytes.Equal(s.TryDecrypt(encS), data) {
		t.Error("TryDecrypt match failed")
	}
	if !bytes.Equal(s.TryDecrypt([]byte("invalid")), []byte("invalid")) {
		t.Error("TryDecrypt fallback failed")
	}

	// Asymmetric
	priv, pub, _ := crypto.GenerateRSAKeyPair(2048)
	a, _ := crypto.NewRSAAndEraseKey(priv, pub)
	encA, _ := a.EncryptBytes(data)

	decA := cast.As(a.DecryptBytes(encA))
	if !bytes.Equal(decA, data) {
		t.Errorf("Asymmetric DecryptBytes with cast.As mismatch: got %s, want %s", string(decA), string(data))
	}

	// Test cast.As for EncryptBytes
	encA2 := cast.As(a.EncryptBytes(data))
	decA2 := cast.As(a.DecryptBytes(encA2))
	if !bytes.Equal(decA2, data) {
		t.Errorf("Asymmetric Encrypt/Decrypt via cast.As failed")
	}

	// Test Sign with cast.As
	sig := cast.As(a.Sign(data))
	if len(sig) == 0 {
		t.Error("Sign with cast.As failed")
	}

	valid, _ := a.Verify(data, sig)
	if !valid {
		t.Error("Verify failed")
	}
}
