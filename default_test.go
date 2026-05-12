package crypto

import (
	"bytes"
	"testing"
)

func TestDefaultAES(t *testing.T) {
	// 1. 测试初始默认值
	var confAES *Symmetric
	OnSetDefaultAES(func(aes *Symmetric) {
		confAES = aes
	})

	if confAES == nil {
		t.Fatal("confAES should be initialized by OnSetDefaultAES")
	}

	// 2. 测试 SetDefaultAES 触发更新与锁定
	rawKey := []byte("12345678901234567890123456789012")
	newKey := bytes.Clone(rawKey)
	newIv := []byte("123456789012")
	SetDefaultAES(newKey, newIv)

	// 验证密钥已被擦除 (ZeroMemory 会用随机 junk 覆盖，所以检查是否不再等于原始值)
	if bytes.Equal(newKey, rawKey) {
		t.Error("newKey should be overwritten after SetDefaultAES")
	}

	// 此时 confAES 应该已经被回调更新了
	data := []byte("hello world")
	encrypted, err := confAES.EncryptAndErase(bytes.Clone(data))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 3. 测试安全性：SetDefaultAES 之后不再允许 OnSetDefaultAES
	var blockedAES *Symmetric
	OnSetDefaultAES(func(aes *Symmetric) {
		blockedAES = aes
	})
	if blockedAES != nil {
		t.Error("OnSetDefaultAES should be blocked after SetDefaultAES (auto-lock)")
	}

	// 4. 测试 SetDefaultAES 仅允许一次
	anotherKey := []byte("another key 32 bytes long.......")
	SetDefaultAES(anotherKey, newIv)
	// 验证密钥没有改变（通过解密验证）
	_, err = confAES.DecryptBytes(encrypted)
	if err != nil {
		t.Errorf("Decryption should still work with the first injected key: %v", err)
	}
}
