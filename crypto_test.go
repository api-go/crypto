package crypto_test

import (
	"bytes"
	"testing"

	lcrypto "apigo.cc/go/crypto"
)

func TestSecurityErase(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	
	// 测试 AndEraseKey 确实擦除了原始内存
	lcrypto.NewAESCBCAndEraseKey(key, iv)
	
	if bytes.Equal(key, []byte("1234567890123456")) {
		t.Fatal("Security Failure: Key was NOT erased")
	}
	if bytes.Equal(iv, []byte("1234567890123456")) {
		t.Fatal("Security Failure: IV was NOT erased")
	}
}

func TestAESExhaustive(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	data := []byte("hello aes exhaustive testing")

	aes, _ := lcrypto.NewAESCBCWithOutEraseKey(key, iv)

	// 1. 正常加解密
	enc, _ := aes.EncryptBytes(data)
	dec, _ := aes.DecryptBytes(enc)
	if !bytes.Equal(data, dec) { t.Fatal("CBC roundtrip failed") }

	// 2. 损坏密文测试 (应能正常处理 Pkcs5UnPadding 失败)
	damaged := append([]byte(nil), enc...)
	damaged[len(damaged)-1] ^= 0xFF
	decN := aes.TryDecrypt(damaged)
	if bytes.Equal(decN, data) {
		t.Fatal("Security Breach: Damaged ciphertext still returned correct plaintext")
	}

	// 3. 非法 Key 长度测试
	_, err := lcrypto.NewAESCBCWithOutEraseKey([]byte("too short"), iv)
	if err == nil {
		t.Fatal("Edge failure: Accepted invalid key size")
	}
}

func TestAsymmetricExhaustive(t *testing.T) {
	// RSA OAEP
	priv, pub, _ := lcrypto.GenerateRSAKeyPair(2048)
	rsa, _ := lcrypto.NewRSAndEraseKey(priv, pub)
	data := []byte("rsa test data")
	
	enc, _ := rsa.EncryptBytes(data)
	dec, _ := rsa.DecryptBytes(enc)
	if !bytes.Equal(data, dec) { t.Fatal("RSA encryption failed") }

	// ECDSA Hybrid (ECDH + AESGCM)
	priv2, pub2, _ := lcrypto.GenerateECDSAKeyPair(256)
	ecdsa, _ := lcrypto.NewECDSAndEraseKey(priv2, pub2)
	enc2, _ := ecdsa.EncryptBytes(data)
	dec2, _ := ecdsa.DecryptBytes(enc2)
	if !bytes.Equal(data, dec2) { t.Fatal("ECDSA Hybrid encryption failed") }
}

func TestAnsiX923Padding(t *testing.T) {
	data := []byte("ansi test")
	blockSize := 16
	padded := lcrypto.AnsiX923Padding(data, blockSize)
	if len(padded) != blockSize {
		t.Fatalf("Padding length mismatch: %d", len(padded))
	}
	if padded[len(padded)-1] != byte(blockSize-len(data)) {
		t.Fatal("Padding length marker incorrect")
	}
	unpadded := lcrypto.AnsiX923UnPadding(padded)
	if !bytes.Equal(data, unpadded) {
		t.Fatal("ANSI X9.23 roundtrip failed")
	}
}

func TestConcurrentSafe(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	aes, _ := lcrypto.NewAESGCMWithOutEraseKey(key, iv)
	data := []byte("concurrent data")

	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			enc, _ := aes.EncryptBytes(data)
			dec, _ := aes.DecryptBytes(enc)
			if !bytes.Equal(data, dec) {
				t.Error("Concurrency breach detected")
			}
			done <- true
		}()
	}
	for i := 0; i < 100; i++ { <-done }
}

// Benchmarks
func BenchmarkAES_GCM(b *testing.B) {
	key := make([]byte, 32)
	iv := make([]byte, 12)
	data := make([]byte, 1024)
	aes, _ := lcrypto.NewAESGCMWithOutEraseKey(key, iv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = aes.EncryptBytes(data)
	}
}

func BenchmarkAES_CBC(b *testing.B) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	data := make([]byte, 1024)
	aes, _ := lcrypto.NewAESCBCWithOutEraseKey(key, iv)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = aes.EncryptBytes(data)
	}
}

func BenchmarkRSA_Sign(b *testing.B) {
	priv, pub, _ := lcrypto.GenerateRSAKeyPair(2048)
	rsa, _ := lcrypto.NewRSAndEraseKey(priv, pub)
	data := []byte("performance test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rsa.Sign(data)
	}
}

func BenchmarkECDSA_Sign(b *testing.B) {
	priv, pub, _ := lcrypto.GenerateECDSAKeyPair(256)
	ecdsa, _ := lcrypto.NewECDSAndEraseKey(priv, pub)
	data := []byte("performance test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ecdsa.Sign(data)
	}
}

func BenchmarkEd25519_Sign(b *testing.B) {
	priv, pub, _ := lcrypto.GenerateEd25519KeyPair()
	ed, _ := lcrypto.NewED25519AndEraseKey(priv, pub)
	data := []byte("performance test")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ed.Sign(data)
	}
}

func BenchmarkX25519_Encrypt(b *testing.B) {
	priv, pub, _ := lcrypto.GenerateX25519KeyPair()
	x, _ := lcrypto.NewX25519AndEraseKey(priv, pub)
	data := []byte("performance test data 1kb")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = x.EncryptBytes(data)
	}
}
