package crypto

import (
	"crypto"
	"runtime"

	"apigo.cc/go/safe"
)

// Asymmetric 封装非对称加密的生命周期与安全存储
type Asymmetric struct {
	algorithm     AsymmetricAlgorithm
	privateKeyBuf *safe.SafeBuf
	publicKeyBuf  *safe.SafeBuf
	privCache     any // FastMode 缓存
	pubCache      any // FastMode 缓存
}

// NewAsymmetric 基于已有的 SafeBuf 创建 Asymmetric
func NewAsymmetric(algorithm AsymmetricAlgorithm, safePrivateKeyBuf, safePublicKeyBuf *safe.SafeBuf) (*Asymmetric, error) {
	a := &Asymmetric{algorithm: algorithm, privateKeyBuf: safePrivateKeyBuf, publicKeyBuf: safePublicKeyBuf}
	runtime.SetFinalizer(a, func(obj *Asymmetric) { obj.Close() })
	return a, nil
}

// NewAsymmetricAndEraseKey 创建并自动擦除传入的密钥
func NewAsymmetricAndEraseKey(algorithm AsymmetricAlgorithm, privateKey, publicKey []byte) (*Asymmetric, error) {
	if privateKey != nil {
		defer safe.ZeroMemory(privateKey)
	}
	if publicKey != nil {
		defer safe.ZeroMemory(publicKey)
	}
	return NewAsymmetricWithoutEraseKey(algorithm, privateKey, publicKey, false)
}

// NewAsymmetricWithoutEraseKey 提供可选的 fastModeButIsNotSecure 以提高高性能场景下的解析性能
func NewAsymmetricWithoutEraseKey(algorithm AsymmetricAlgorithm, privateKey, publicKey []byte, fastModeButIsNotSecure bool) (*Asymmetric, error) {
	a := &Asymmetric{algorithm: algorithm}
	var err error
	if privateKey != nil {
		if fastModeButIsNotSecure {
			if a.privCache, err = algorithm.ParsePrivateKey(privateKey); err != nil {
				return nil, err
			}
		} else {
			a.privateKeyBuf = safe.NewSafeBuf(privateKey)
		}
	}
	if publicKey != nil {
		if fastModeButIsNotSecure {
			if a.pubCache, err = algorithm.ParsePublicKey(publicKey); err != nil {
				return nil, err
			}
		} else {
			a.publicKeyBuf = safe.NewSafeBuf(publicKey)
		}
	}
	runtime.SetFinalizer(a, func(obj *Asymmetric) { obj.Close() })
	return a, nil
}

// Close 销毁实例并擦除敏感数据
func (a *Asymmetric) Close() {
	if a.privateKeyBuf != nil {
		a.privateKeyBuf.Close()
		a.privateKeyBuf = nil
	}
	if a.publicKeyBuf != nil {
		a.publicKeyBuf.Close()
		a.publicKeyBuf = nil
	}
}

// Sign 进行签名逻辑
func (a *Asymmetric) Sign(data []byte, hash ...crypto.Hash) ([]byte, error) {
	if a.privCache != nil {
		return a.algorithm.Sign(a.privCache, data, hash...)
	}
	if a.privateKeyBuf == nil {
		return nil, ErrPrivKeyMissing
	}
	sp := a.privateKeyBuf.Open()
	defer sp.Close()
	privKey, err := a.algorithm.ParsePrivateKey(sp.Data)
	if err != nil {
		return nil, err
	}
	return a.algorithm.Sign(privKey, data, hash...)
}

// Verify 进行验签逻辑
func (a *Asymmetric) Verify(data []byte, signature []byte, hash ...crypto.Hash) (bool, error) {
	if a.pubCache != nil {
		return a.algorithm.Verify(a.pubCache, data, signature, hash...)
	}
	if a.publicKeyBuf == nil {
		return false, ErrPubKeyMissing
	}
	sp := a.publicKeyBuf.Open()
	defer sp.Close()
	pubKey, err := a.algorithm.ParsePublicKey(sp.Data)
	if err != nil {
		return false, err
	}
	return a.algorithm.Verify(pubKey, data, signature, hash...)
}

// Encrypt 使用公钥进行非对称加密
func (a *Asymmetric) Encrypt(data []byte) ([]byte, error) {
	cipherAlgo, ok := a.algorithm.(AsymmetricCipherAlgorithm)
	if !ok {
		return nil, ErrAlgorithmNoEncrypt
	}
	if a.pubCache != nil {
		return cipherAlgo.Encrypt(a.pubCache, data)
	}
	if a.publicKeyBuf == nil {
		return nil, ErrPubKeyMissing
	}
	sp := a.publicKeyBuf.Open()
	defer sp.Close()
	pubKey, err := a.algorithm.ParsePublicKey(sp.Data)
	if err != nil {
		return nil, err
	}
	return cipherAlgo.Encrypt(pubKey, data)
}

// Decrypt 使用私钥进行非对称解密
func (a *Asymmetric) Decrypt(data []byte) ([]byte, error) {
	cipherAlgo, ok := a.algorithm.(AsymmetricCipherAlgorithm)
	if !ok {
		return nil, ErrAlgorithmNoDecrypt
	}
	if a.privCache != nil {
		return cipherAlgo.Decrypt(a.privCache, data)
	}
	if a.privateKeyBuf == nil {
		return nil, ErrPrivKeyMissing
	}
	sp := a.privateKeyBuf.Open()
	defer sp.Close()
	privKey, err := a.algorithm.ParsePrivateKey(sp.Data)
	if err != nil {
		return nil, err
	}
	return cipherAlgo.Decrypt(privKey, data)
}
