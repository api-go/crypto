package crypto

import (
	"crypto/sha256"
	"io"

	"apigo.cc/go/safe"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Default Argon2id parameters
const (
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024 // 64MB
	Argon2Threads = 4
)

// DeriveKey using Argon2id and automatically erases password and salt
func DeriveKey(password, salt []byte, keyLen uint32) []byte {
	defer safe.ZeroMemory(password)
	defer safe.ZeroMemory(salt)
	return argon2.IDKey(password, salt, Argon2Time, Argon2Memory, Argon2Threads, keyLen)
}

// NewDeterministicReader creates an io.Reader that produces a deterministic stream of bytes from a seed.
// This is used to make RSA/ECDSA key generation deterministic based on a password.
func NewDeterministicReader(seed []byte, info []byte) io.Reader {
	return hkdf.New(sha256.New, seed, nil, info)
}
