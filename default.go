package crypto

import (
	"errors"
	"sync"

	"github.com/api-go/safe"
)

var (
	// defaultAES 用于配置解密的默认 AES 实例 (私有)
	defaultAES *Symmetric

	defaultAESHandlers []func(*Symmetric)
	defaultAESLock     sync.RWMutex
	defaultAESOnce     sync.Once
	isDefaultAESSet    bool
	isLocked           bool
)

func init() {
	// 默认硬编码密钥，仅用于基础防护。
	defaultAES, _ = NewAESGCMWithoutEraseKey(
		[]byte("?GQ$0K0GgLdO=f+~L68PLm$uhKr4'=tV"),
		[]byte("VFs7@sK61cj^f?HZ"),
	)
}

// OnSetDefaultAES 注册配置解密 AES 实例变更的回调。
// 必须在 SetDefaultAES 或 SetDefaultAESFromSafeBuf 成功安装前注册。
// 注册时立即以当前实例调用一次，安装后会收到新实例；安装成功后禁止新增注册。
func OnSetDefaultAES(h func(*Symmetric)) {
	defaultAESLock.Lock()
	defer defaultAESLock.Unlock()

	if isLocked {
		// 如果已经锁定，不再允许注册新的回调
		return
	}

	defaultAESHandlers = append(defaultAESHandlers, h)
	if defaultAES != nil {
		h(defaultAES)
	}
}

// SetDefaultAES 设置全局默认 AES 密钥与 IV。
// 仅允许调用一次。调用后会立即锁定注册通道，后续 OnSetDefaultAES 将不再起作用。
// 注意：此方法会自动擦除 (ZeroMemory) 传入的 key 和 iv 字节切片。
func SetDefaultAES(key, iv []byte) {
	defaultAESOnce.Do(func() {
		// 创建新实例并擦除原始密钥
		newAES, err := NewAESGCMAndEraseKey(key, iv)
		if err != nil {
			return
		}

		defaultAESLock.Lock()
		defer defaultAESLock.Unlock()

		defaultAES = newAES
		isLocked = true

		// 通知所有在初始化阶段注册的观察者
		for _, h := range defaultAESHandlers {
			h(defaultAES)
		}

		// 彻底清理并释放引用
		defaultAESHandlers = nil
	})
}

// SetDefaultAESFromSafeBuf installs default AES without an unprotected input API.
// Success transfers ownership of key and iv to the default AES: callers must not
// close or modify them afterward. On error the caller retains both objects.
// Registers the same one-shot observer lock as SetDefaultAES. Do not call from an observer.
func SetDefaultAESFromSafeBuf(key, iv *safe.SafeBuf) error {
	if key == nil || iv == nil || key == iv {
		return errors.New("crypto: distinct key and IV buffers required")
	}
	plainKey, plainIV := key.Open(), iv.Open()
	keySize, ivSize := len(plainKey.Data), len(plainIV.Data)
	plainKey.Close()
	plainIV.Close()
	if (keySize != 16 && keySize != 24 && keySize != 32) || ivSize < 12 || ivSize > 16 {
		return errors.New("crypto: invalid default AES key or IV length")
	}
	installed := false
	defaultAESOnce.Do(func() {
		defaultAESLock.Lock()
		defer defaultAESLock.Unlock()
		defaultAES, _ = NewAESGCM(key, iv)
		isLocked = true
		installed = true
		for _, handler := range defaultAESHandlers {
			handler(defaultAES)
		}
		defaultAESHandlers = nil
	})
	if !installed {
		return errors.New("crypto: default AES already set")
	}
	return nil
}
