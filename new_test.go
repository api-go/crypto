package crypto_test

import (
	"bytes"
	"testing"

	"apigo.cc/go/crypto"
)

func TestMustAndTryMethods(t *testing.T) {
	// Setup
	priv, pub, _ := crypto.GenerateRSAKeyPair(2048)
	a, _ := crypto.NewRSAWithoutEraseKey(priv, pub)
	data := []byte("secret")
	
	// Symmetric
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	s, _ := crypto.NewAESGCMWithoutEraseKey(key, iv)
	encS, _ := s.EncryptBytes(data)

	// Tests
	if !bytes.Equal(s.MustEncrypt(data), encS) {
		t.Error("MustEncrypt mismatch")
	}
	if !bytes.Equal(s.MustDecrypt(encS), data) {
		t.Error("MustDecrypt mismatch")
	}
	if !bytes.Equal(s.TryDecrypt([]byte("bad")), []byte("bad")) {
		t.Error("TryDecrypt should return original on error")
	}
	
	// Re-encrypt to get fresh ciphertext for asymmetric
	encA, _ := a.EncryptBytes(data)
	decA := a.MustDecrypt(encA)
	if !bytes.Equal(decA, data) {
		t.Errorf("Asymmetric MustDecrypt mismatch: got %s, want %s", string(decA), string(data))
	}
	
	// Test MustEncrypt specifically (e.g. check it works at all)
	encA2 := a.MustEncrypt(data)
	decA2 := a.MustDecrypt(encA2)
	if !bytes.Equal(decA2, data) {
		t.Errorf("Asymmetric MustEncrypt/Decrypt failed")
	}

	if !bytes.Equal(a.TryDecrypt([]byte("bad")), []byte("bad")) {
		t.Error("Asymmetric TryDecrypt should return original on error")
	}
	if len(a.MustSign(data)) == 0 {
		t.Error("MustSign failed")
	}
}
