package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/api-go/safe"
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
	return newExpandingHKDFReader(seed, info)
}

type expandingHKDFReader struct {
	seed    []byte
	info    []byte
	round   uint64
	current io.Reader
}

func newExpandingHKDFReader(seed, info []byte) io.Reader {
	r := &expandingHKDFReader{
		seed: append([]byte(nil), seed...),
		info: append([]byte(nil), info...),
	}
	r.reset()
	return r
}

func (r *expandingHKDFReader) reset() {
	info := r.info
	if r.round > 0 {
		info = make([]byte, len(r.info)+8)
		copy(info, r.info)
		binary.BigEndian.PutUint64(info[len(r.info):], r.round)
	}
	r.current = hkdf.New(sha256.New, r.seed, nil, info)
	r.round++
}

func (r *expandingHKDFReader) Read(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := r.current.Read(p[total:])
		total += n
		if err == nil {
			continue
		}
		r.reset()
	}
	return total, nil
}
