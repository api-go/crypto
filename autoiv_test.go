package crypto_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"sync"
	"testing"

	crypto "github.com/api-go/crypto"
	"github.com/api-go/safe"
)

func TestAutoIVCompatibility(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	iv := bytes.Repeat([]byte{9}, 16)
	sender, err := crypto.NewAESGCMWithoutEraseKey(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := crypto.NewAESGCMWithoutEraseKey(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	block, _ := aes.NewCipher(key)
	raw, _ := cipher.NewGCM(block)
	for _, size := range []int{0, 1, 11, 12, 15, 16, 17, 128, 4096} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			plain := bytes.Repeat([]byte{3}, size)
			legacy := raw.Seal(nil, iv[:12], plain, nil)
			fixed, err := sender.EncryptBytes(plain)
			if err != nil || !bytes.Equal(fixed, legacy) {
				t.Fatal("legacy wire changed", err)
			}
			modern, err := sender.EncryptBytesAutoIV(plain)
			if err != nil {
				t.Fatal(err)
			}
			other, err := sender.EncryptBytesAutoIV(plain)
			if err != nil || bytes.Equal(modern[:12], other[:12]) {
				t.Fatal("nonce reused", err)
			}
			if len(modern) != size+28 {
				t.Fatal("unexpected wire length")
			}
			// Independent standard-library decoder proves nonce/ciphertext/tag layout.
			decoded, err := raw.Open(nil, modern[:12], modern[12:], nil)
			if err != nil || !bytes.Equal(decoded, plain) {
				t.Fatal("wire incompatible", err)
			}
			for _, encrypted := range [][]byte{legacy, modern} {
				decoded, err := receiver.DecryptBytes(encrypted)
				if err != nil || !bytes.Equal(decoded, plain) {
					t.Fatal("compatibility", err)
				}
				protected, err := receiver.Decrypt(encrypted)
				if err != nil {
					t.Fatal(err)
				}
				protected.Close()
			}
			for _, index := range []int{0, 12, len(modern) - 1} {
				damaged := bytes.Clone(modern)
				damaged[index] ^= 1
				if _, err := receiver.DecryptBytes(damaged); err == nil {
					t.Fatal("tamper accepted")
				}
			}
		})
	}
	// A legacy ciphertext whose first 12 bytes equal the IV must still fall back.
	plain := make([]byte, 64)
	zeroCipher := raw.Seal(nil, iv[:12], plain, nil)
	for i := 0; i < 12; i++ {
		plain[i] = zeroCipher[i] ^ iv[i]
	}
	legacy := raw.Seal(nil, iv[:12], plain, nil)
	if !bytes.Equal(legacy[:12], iv[:12]) {
		t.Fatal("fixture")
	}
	if got, err := receiver.DecryptBytes(legacy); err != nil || !bytes.Equal(got, plain) {
		t.Fatal("fallback", err)
	}
	wrong, _ := crypto.NewAESGCMWithoutEraseKey(bytes.Repeat([]byte{8}, 32), iv)
	defer wrong.Close()
	if _, err := wrong.DecryptBytes(legacy); err == nil {
		t.Fatal("wrong key accepted")
	}
	for n := 0; n < 28; n++ {
		if _, err := receiver.DecryptBytes(make([]byte, n)); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	keyOnly, _ := crypto.NewAESGCMWithoutEraseKey(key, nil)
	defer keyOnly.Close()
	modern, _ := keyOnly.EncryptBytesAutoIV(plain)
	if got, err := keyOnly.DecryptBytes(modern); err != nil || !bytes.Equal(got, plain) {
		t.Fatal("key only", err)
	}
	if _, err := keyOnly.DecryptBytes(legacy); err == nil {
		t.Fatal("legacy needs IV")
	}
	if _, err := crypto.AESGCM.Decrypt(legacy, key, nil); err == nil {
		t.Fatal("short IV accepted")
	}
}

func TestAutoIVProtectedEraseAndConcurrent(t *testing.T) {
	s, _ := crypto.NewAESGCMWithoutEraseKey(bytes.Repeat([]byte{1}, 32), nil)
	defer s.Close()
	input := safe.NewSafeBuf([]byte("protected"))
	defer input.Close()
	encrypted, err := s.EncryptAutoIV(input)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.DecryptBytes(encrypted); err != nil || string(got) != "protected" {
		t.Fatal(err)
	}
	plain := []byte("erase me")
	if _, err := s.EncryptAndEraseAutoIV(plain); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(plain, []byte("erase me")) {
		t.Fatal("plaintext retained")
	}
	cbc, _ := crypto.NewAESCBCWithoutEraseKey(bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16))
	defer cbc.Close()
	plain = []byte("erase on failure")
	if _, err := cbc.EncryptAndEraseAutoIV(plain); !errors.Is(err, crypto.ErrNotImplemented) {
		t.Fatal(err)
	}
	if bytes.Equal(plain, []byte("erase on failure")) {
		t.Fatal("failure retained plaintext")
	}
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			enc, err := s.EncryptBytesAutoIV([]byte("concurrent"))
			if err != nil {
				t.Error(err)
				return
			}
			dec, err := s.DecryptBytes(enc)
			if err != nil || string(dec) != "concurrent" {
				t.Error("concurrent", err)
			}
		})
	}
	workers.Wait()
}

// Legacy engines implementing only the original interface remain supported.
type legacyGCM struct{}

func (legacyGCM) Encrypt(data, key, iv []byte) ([]byte, error) {
	return crypto.AESGCM.Encrypt(data, key, iv)
}
func (legacyGCM) Decrypt(data, key, iv []byte) ([]byte, error) {
	return crypto.AESGCM.Decrypt(data, key, iv)
}
func TestLegacyEngineCompatibility(t *testing.T) {
	s, err := crypto.NewSymmetricWithoutEraseKey(legacyGCM{}, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 12))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	enc, err := s.EncryptBytes([]byte("legacy engine"))
	if err != nil {
		t.Fatal(err)
	}
	dec, err := s.DecryptBytes(enc)
	if err != nil || string(dec) != "legacy engine" {
		t.Fatal(err)
	}
	if _, err := s.EncryptBytesAutoIV(nil); !errors.Is(err, crypto.ErrNotImplemented) {
		t.Fatal(err)
	}
}

func BenchmarkGCMCompatible(b *testing.B) {
	key := bytes.Repeat([]byte{1}, 32)
	iv := bytes.Repeat([]byte{2}, 12)
	s, _ := crypto.NewAESGCMWithoutEraseKey(key, iv)
	defer s.Close()
	baseline, _ := crypto.NewSymmetricWithoutEraseKey(legacyGCM{}, key, iv)
	defer baseline.Close()
	for _, size := range []int{64, 4096, 1048576} {
		plain := make([]byte, size)
		legacy, _ := s.EncryptBytes(plain)
		modern, _ := s.EncryptBytesAutoIV(plain)
		for _, mode := range []string{"ExplicitLegacy", "SymmetricLegacy", "CompatibleLegacy", "CompatibleAutoIV", "EncryptAutoIV"} {
			b.Run(fmt.Sprintf("%d/%s", size, mode), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					var err error
					switch mode {
					case "ExplicitLegacy":
						_, err = crypto.AESGCM.Decrypt(legacy, key, iv)
					case "SymmetricLegacy":
						_, err = baseline.DecryptBytes(legacy)
					case "CompatibleLegacy":
						_, err = s.DecryptBytes(legacy)
					case "CompatibleAutoIV":
						_, err = s.DecryptBytes(modern)
					case "EncryptAutoIV":
						_, err = s.EncryptBytesAutoIV(plain)
					}
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
