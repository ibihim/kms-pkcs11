package kms

import (
	"github.com/google/tink/go/aead"
)

func (k *KeyChain) Encrypt(plaintext []byte) ([]byte, error) {
	return k.EncryptWithAAD(plaintext, []byte{})
}

func (k *KeyChain) EncryptWithAAD(plaintext, additionalData []byte) ([]byte, error) {
	if !k.validToUse() {
		if err := k.Rotate(); err != nil {
			return nil, err
		}
	}

	a, err := aead.New(k.kek)
	if err != nil {
		return nil, err
	}

	ct, err := a.Encrypt(plaintext, additionalData)
	if err != nil {
		return nil, err
	}

	k.incrementUsageCounter()

	return ct, err
}

func (k *KeyChain) Decrypt(encryptedData []byte) ([]byte, error) {
	return k.DecryptWithAAD(encryptedData, []byte{})
}

func (k *KeyChain) DecryptWithAAD(ciphertext, additionalData []byte) ([]byte, error) {
	a, err := aead.New(k.kek)
	if err != nil {
		return nil, err
	}

	plaintext, err := a.Decrypt(ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
