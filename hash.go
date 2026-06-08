package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"

	"apigo.cc/go/encoding"
)

// MD5 返回数据的原始 MD5 字节
func MD5(data ...[]byte) []byte {
	h := md5.New()
	for _, v := range data {
		h.Write(v)
	}
	return h.Sum(nil)
}

// MD5ToHex 返回 MD5 的 Hex 字符串
func MD5ToHex(data []byte) string {
	return encoding.Hex(MD5(data))
}

// MD5ToBase64 返回 MD5 的 Base64 字符串
func MD5ToBase64(data []byte) string {
	return encoding.Base64(MD5(data))
}

// MD5ToURLBase64 返回 MD5 的 URL 安全 Base64 字符串
func MD5ToURLBase64(data []byte) string {
	return encoding.URLBase64(MD5(data))
}

// Sha1 系列
func Sha1(data ...[]byte) []byte {
	h := sha1.New()
	for _, v := range data {
		h.Write(v)
	}
	return h.Sum(nil)
}

func Sha1ToHex(data []byte) string { return encoding.Hex(Sha1(data)) }
func Sha1ToBase64(data []byte) string { return encoding.Base64(Sha1(data)) }
func Sha1ToURLBase64(data []byte) string { return encoding.URLBase64(Sha1(data)) }

// Sha256 系列
func Sha256(data ...[]byte) []byte {
	h := sha256.New()
	for _, v := range data {
		h.Write(v)
	}
	return h.Sum(nil)
}

func Sha256ToHex(data []byte) string { return encoding.Hex(Sha256(data)) }
func Sha256ToBase64(data []byte) string { return encoding.Base64(Sha256(data)) }
func Sha256ToURLBase64(data []byte) string { return encoding.URLBase64(Sha256(data)) }

// Sha512 系列
func Sha512(data ...[]byte) []byte {
	h := sha512.New()
	for _, v := range data {
		h.Write(v)
	}
	return h.Sum(nil)
}

func Sha512ToHex(data []byte) string { return encoding.Hex(Sha512(data)) }
func Sha512ToBase64(data []byte) string { return encoding.Base64(Sha512(data)) }
func Sha512ToURLBase64(data []byte) string { return encoding.URLBase64(Sha512(data)) }

// HMAC 系列
func HMACMD5(key []byte, data ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, v := range data {
		h.Write(v)
	}
	return h.Sum(nil)
}

func HMACSha1(key []byte, data ...[]byte) []byte {
	h := hmac.New(sha1.New, key)
	for _, v := range data {
		h.Write(v)
	}
	return h.Sum(nil)
}

func HMACSha256(key []byte, data ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, v := range data {
		h.Write(v)
	}
	return h.Sum(nil)
}

func HMACSha512(key []byte, data ...[]byte) []byte {
	h := hmac.New(sha512.New, key)
	for _, v := range data {
		h.Write(v)
	}
	return h.Sum(nil)
}

// MakeToken 生成随机令牌
func MakeToken(size int) []byte {
	token := make([]byte, size)
	rand.Read(token)
	return token
}
