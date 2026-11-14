package crypto_test

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"testing"

	crypto "github.com/api-go/crypto"
	"github.com/api-go/safe"
)

// Isolate the once-only default from existing tests and verify ownership after GC.
func TestDefaultAESFromSafeBuf(t *testing.T) {
	if os.Getenv("GO_CRYPTO_SAFE_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestDefaultAESFromSafeBuf$")
		command.Env = append(os.Environ(), "GO_CRYPTO_SAFE_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, output)
		}
		return
	}
	var current *crypto.Symmetric
	crypto.OnSetDefaultAES(func(s *crypto.Symmetric) { current = s })
	key := safe.NewSafeBuf(bytes.Repeat([]byte{0x37}, 32))
	iv := safe.NewSafeBuf(bytes.Repeat([]byte{0x51}, 16))
	short := safe.NewSafeBuf([]byte{1})
	defer short.Close()
	if err := crypto.SetDefaultAESFromSafeBuf(nil, iv); err == nil {
		t.Fatal("nil accepted")
	}
	if err := crypto.SetDefaultAESFromSafeBuf(key, key); err == nil {
		t.Fatal("aliased input accepted")
	}
	if err := crypto.SetDefaultAESFromSafeBuf(short, iv); err == nil {
		t.Fatal("short key accepted")
	}
	if err := crypto.SetDefaultAESFromSafeBuf(key, short); err == nil {
		t.Fatal("short IV accepted")
	}
	if err := crypto.SetDefaultAESFromSafeBuf(key, iv); err != nil {
		key.Close()
		iv.Close()
		t.Fatal(err)
	}
	key, iv = nil, nil
	runtime.GC()
	encrypted, err := current.EncryptBytesAutoIV([]byte("ownership transfer"))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := crypto.NewAESGCMWithoutEraseKey(bytes.Repeat([]byte{0x37}, 32), bytes.Repeat([]byte{0x51}, 16))
	if err != nil {
		t.Fatal(err)
	}
	defer expected.Close()
	plain, err := expected.DecryptBytes(encrypted)
	if err != nil || !bytes.Equal(plain, []byte("ownership transfer")) {
		t.Fatal("wrong default", err)
	}
	other := safe.NewSafeBuf(bytes.Repeat([]byte{0x41}, 32))
	defer other.Close()
	otherIV := safe.NewSafeBuf(bytes.Repeat([]byte{0x42}, 12))
	defer otherIV.Close()
	if err := crypto.SetDefaultAESFromSafeBuf(other, otherIV); err == nil {
		t.Fatal("second install accepted")
	}
	check := other.Open()
	defer check.Close()
	if !bytes.Equal(check.Data, bytes.Repeat([]byte{0x41}, 32)) {
		t.Fatal("error consumed input")
	}
	blocked := false
	crypto.OnSetDefaultAES(func(*crypto.Symmetric) { blocked = true })
	if blocked {
		t.Fatal("observer not locked")
	}
	crypto.SetDefaultAES(bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{9}, 12))
	plain, err = current.DecryptBytes(encrypted)
	if err != nil || !bytes.Equal(plain, []byte("ownership transfer")) {
		t.Fatal("legacy setter overwrote default", err)
	}
}
