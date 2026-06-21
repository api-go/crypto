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
	if !bytes.Equal(crypto.SHA256(data), h2[:]) { t.Error("SHA256 mismatch") }
	
	// HMAC
	key := []byte("key")
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	if !bytes.Equal(crypto.HMACSHA256(key, data), mac.Sum(nil)) { t.Error("HMACSHA256 mismatch") }
}

func TestHashString(t *testing.T) {
	s := []byte("hello")
	if crypto.MD5ToHex(s) == "" { t.Error("MD5ToHex empty") }
	if crypto.SHA256ToBase64(s) == "" { t.Error("SHA256ToBase64 empty") }
}
