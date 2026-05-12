package crypto

import (
	"sync"
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
// 即使在 SetDefaultAES 调用之后，此方法仍然有效，直到调用 LockDefaultAES。
// 注册时会立即以当前实例（硬编码或已注入的生产密钥）调用一次回调。
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
