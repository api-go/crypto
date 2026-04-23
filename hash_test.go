package crypto_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"testing"

	"apigo.cc/go/crypto"
)

func TestHashCompatibility(t *testing.T) {
	data := []byte("hello world")
	
	// MD5
	h1 := md5.Sum(data)
	if !bytes.Equal(crypto.MD5(data), h1[:]) { t.Error("MD5 mismatch") }
	
	// SHA256
	h2 := sha256.Sum256(data)
	if !bytes.Equal(crypto.Sha256(data), h2[:]) { t.Error("Sha256 mismatch") }
	
	// HMAC
	key := []byte("key")
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	if !bytes.Equal(crypto.HmacSha256(key, data), mac.Sum(nil)) { t.Error("HmacSha256 mismatch") }
}

func TestHashString(t *testing.T) {
	s := []byte("hello")
	if crypto.MD5ToHex(s) == "" { t.Error("MD5ToHex empty") }
	if crypto.Sha256ToBase64(s) == "" { t.Error("Sha256ToBase64 empty") }
}
