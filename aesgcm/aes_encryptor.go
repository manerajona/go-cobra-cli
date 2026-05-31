package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
)

type Encryptor interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type encryptor struct {
	key, iv []byte
}

func deriveKeyAndIV(key, iv string) ([]byte, []byte) {
	keyHash := sha256.Sum256([]byte(key))
	ivHash := sha256.Sum256([]byte(iv))
	return keyHash[:], ivHash[:12]
}

func NewEncryptor(key, iv string) (Encryptor, error) {
	if len(key) != 64 {
		return nil, aes.KeySizeError(len(key))
	}
	if len(iv) != 32 {
		return nil, aes.KeySizeError(len(iv))
	}
	aesKey, aesIV := deriveKeyAndIV(key, iv)
	return &encryptor{key: aesKey, iv: aesIV}, nil
}

func (e *encryptor) Encrypt(plaintext string) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nil, e.iv, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (e *encryptor) Decrypt(ciphertextB64 string) (string, error) {
	if len(ciphertextB64) == 0 {
		return "", nil
	}
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	plaintext, err := aesgcm.Open(nil, e.iv, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
