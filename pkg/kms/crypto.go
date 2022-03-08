package kms

import (
	"fmt"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/keyset"
)

func (k *KeyChain) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	if !k.validToUse() {
		if err := k.Rotate(); err != nil {
			return nil, err
		}
	}

	dek, ct, err := encryptPlaintext(plaintext, additionalData)
	if err != nil {
		return nil, err
	}

	// store in memory, TODO use kubernetes LRU cache
	prefix := ct[:cryptofmt.NonRawPrefixSize]
	k.deks[string(prefix)] = dek

	encDec, err := k.encryptDEK(dek)
	if err != nil {
		return nil, err
	}

	k.incrementUsageCounter()
	return encode(encDec, ct) // TODO combine encode and encrypt so none is used without the other.
}

func encryptPlaintext(plaintext, additionalData []byte) (*keyset.Handle, []byte, error) {
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, nil, err
	}

	a, err := aead.New(kh)
	if err != nil {
		return nil, nil, err
	}

	ct, err := a.Encrypt(plaintext, additionalData)
	if err != nil {
		return nil, nil, err
	}

	return kh, ct, nil
}

func (k *KeyChain) Decrypt(encryptedData, additionalData []byte) ([]byte, error) {
	encDec, ct, err := decode(encryptedData)
	if err != nil {
		return nil, err
	}

	prefix := ct[:cryptofmt.NonRawPrefixSize]
	dek, ok := k.deks[string(prefix)]
	if !ok {
		dek, err = k.decryptDEK(encDec)
		if err != nil {
			return nil, fmt.Errorf("can't find nor decrypt DEK: %w", err)
		}
	}

	return decryptPlaintext(dek, ct, additionalData)
}

func decryptPlaintext(dek *keyset.Handle, ciphertext, additionalData []byte) ([]byte, error) {
	a, err := aead.New(dek)
	if err != nil {
		return nil, err
	}

	plaintext, err := a.Decrypt(ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
