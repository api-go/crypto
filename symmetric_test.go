package crypto_test

import (
	"bytes"
	"testing"

	"apigo.cc/go/crypto"
)

func TestSymmetricObfuscation(t *testing.T) {
	// 传入 64 字节密钥，应自动截断为 32 字节使用
	longKey := bytes.Repeat([]byte{0x01}, 64)
	iv := bytes.Repeat([]byte{0x02}, 16)
	data := []byte("secret data")

	aes, err := crypto.NewAESGCMWithoutEraseKey(longKey, iv)
	if err != nil { t.Fatal(err) }
	
	enc, err := aes.EncryptBytes(data)
	if err != nil { t.Fatal(err) }
	
	dec, err := aes.DecryptBytes(enc)
	if err != nil { t.Fatal(err) }
	
	if !bytes.Equal(data, dec) { t.Error("Decryption failed with long key") }
}

func TestSymmetricPadding(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	data := []byte("test padding data")

	// PKCS5 (Default)
	aes, _ := crypto.NewAESCBCWithoutEraseKey(key, iv)
	enc, _ := aes.EncryptBytes(data)
	dec, _ := aes.DecryptBytes(enc)
	if !bytes.Equal(data, dec) { t.Error("PKCS5 roundtrip failed") }

	// 模拟损坏密文导致填充错误
	damaged := append([]byte(nil), enc...)
	damaged[len(damaged)-1] ^= 0xFF
	if d := aes.TryDecrypt(damaged); bytes.Equal(d, data) {
		t.Error("Should detect padding error in damaged ciphertext")
	}
}

func TestConcurrentSymmetric(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	aes, _ := crypto.NewAESGCMWithoutEraseKey(key, iv)
	data := []byte("concurrent")

	for i := 0; i < 50; i++ {
		t.Run("Concurrent", func(t *testing.T) {
			t.Parallel()
			enc, _ := aes.EncryptBytes(data)
			dec, _ := aes.DecryptBytes(enc)
			if !bytes.Equal(data, dec) { t.Error("Data race detected") }
		})
	}
}
