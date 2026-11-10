package crypto_test

import (
	"bytes"
	"testing"

	"github.com/api-go/crypto"
)

func TestPasswordBasedAES(t *testing.T) {
	password := []byte("secret-password")
	salt := []byte("fixed-salt")
	data := []byte("hello world password")

	// Test GCM
	p1 := append([]byte(nil), password...)
	s1 := append([]byte(nil), salt...)
	aesGCM, err := crypto.NewAESGCMByPassword(p1, s1)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := aesGCM.EncryptBytes(data)
	dec, _ := aesGCM.DecryptBytes(enc)
	if !bytes.Equal(data, dec) {
		t.Error("AES-GCM password-based roundtrip failed")
	}

	// Test CBC
	p2 := append([]byte(nil), password...)
	s2 := append([]byte(nil), salt...)
	aesCBC, err := crypto.NewAESCBCByPassword(p2, s2)
	if err != nil {
		t.Fatal(err)
	}
	enc2, _ := aesCBC.EncryptBytes(data)
	dec2, _ := aesCBC.DecryptBytes(enc2)
	if !bytes.Equal(data, dec2) {
		t.Error("AES-CBC password-based roundtrip failed")
	}

	// Verify EraseKey (best effort check - though they are zeroed inside factory)
	if bytes.Equal(p1, []byte("secret-password")) {
		t.Error("Password 1 was not erased")
	}
	if bytes.Equal(s1, []byte("fixed-salt")) {
		t.Error("Salt 1 was not erased")
	}
}

func TestPasswordBasedAsymmetric(t *testing.T) {
	password := []byte("asymm-password")
	salt := []byte("asymm-salt")
	data := []byte("hello asymm")

	// 1. RSA
	p1 := append([]byte(nil), password...)
	s1 := append([]byte(nil), salt...)
	rsa, err := crypto.NewRSAByPassword(p1, s1)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := rsa.EncryptBytes(data)
	dec, _ := rsa.DecryptBytes(enc)
	if !bytes.Equal(data, dec) {
		t.Error("RSA password-based roundtrip failed")
	}

	// 2. ECDSA
	p2 := append([]byte(nil), password...)
	s2 := append([]byte(nil), salt...)
	ecdsa, err := crypto.NewECDSAByPassword(p2, s2)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := ecdsa.Sign(data)
	if ok, _ := ecdsa.Verify(data, sig); !ok {
		t.Error("ECDSA password-based sign/verify failed")
	}

	// 3. Ed25519
	p3 := append([]byte(nil), password...)
	s3 := append([]byte(nil), salt...)
	ed, err := crypto.NewED25519ByPassword(p3, s3)
	if err != nil {
		t.Fatal(err)
	}
	sig2, _ := ed.Sign(data)
	if ok, _ := ed.Verify(data, sig2); !ok {
		t.Error("Ed25519 password-based failed")
	}

	// 4. X25519
	p4 := append([]byte(nil), password...)
	s4 := append([]byte(nil), salt...)
	x, err := crypto.NewX25519ByPassword(p4, s4)
	if err != nil {
		t.Fatal(err)
	}
	enc2, _ := x.EncryptBytes(data)
	dec2, _ := x.DecryptBytes(enc2)
	if !bytes.Equal(data, dec2) {
		t.Error("X25519 password-based roundtrip failed")
	}
}

func TestDeterministicGeneration(t *testing.T) {
	password := []byte("determ-pass")
	salt := []byte("determ-salt")

	// Two instances with same password/salt should have same public key
	p1 := append([]byte(nil), password...)
	s1 := append([]byte(nil), salt...)
	ed1, _ := crypto.NewED25519ByPassword(p1, s1)

	p2 := append([]byte(nil), password...)
	s2 := append([]byte(nil), salt...)
	ed2, _ := crypto.NewED25519ByPassword(p2, s2)

	// Since we don't have GetPublicKeyBytes, we can test by signing with ed1 and verifying with ed2 (if public keys match)
	data := []byte("test")
	sig, _ := ed1.Sign(data)
	if ok, _ := ed2.Verify(data, sig); !ok {
		t.Error("Deterministic generation failed (Ed25519): public keys do not match")
	}

	// Test ECDSA determinism
	p3 := append([]byte(nil), password...)
	s3 := append([]byte(nil), salt...)
	ec1, _ := crypto.NewECDSAByPassword(p3, s3)

	p4 := append([]byte(nil), password...)
	s4 := append([]byte(nil), salt...)
	ec2, _ := crypto.NewECDSAByPassword(p4, s4)

	sig2, _ := ec1.Sign(data)
	if ok, _ := ec2.Verify(data, sig2); !ok {
		t.Error("Deterministic generation failed (ECDSA): public keys do not match")
	}
}
