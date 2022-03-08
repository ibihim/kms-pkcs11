package kms

import (
	"bytes"
	"errors"
	"io"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/keyset"
)

type KeyChain struct {
	kek  *keyset.Handle
	deks map[string]*keyset.Handle
}

type EncryptedKeyChain struct {
	encryptedKEK  [][]byte
	encryptedDEKS map[string][]byte
}

func New(store io.Writer) (*KeyChain, error) {
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, err
	}

	return &KeyChain{kek: kh}, nil
}

func (k *KeyChain) Read(rootKey []byte) error {

	return nil
}

func (k *KeyChain) Write(w io.Writer, rootKey []byte) error {
	var encK EncryptedKeyChain

	a, err := aead.New(k.kek)
	if err != nil {
		return err
	}

	for k, v := range k.deks {
		var buf bytes.Buffer

		var buf bytes.Buffer
		v.Write(keyset.NewBinaryWriter(buf), k.kek)
	}

	return nil
}

func (k *KeyChain) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, err
	}

	a, err := aead.New(kh)
	if err != nil {
		return nil, err
	}

	ct, err := a.Encrypt(plaintext, additionalData)
	if err != nil {
		return nil, err
	}

	prefix := ct[:cryptofmt.NonRawPrefixSize]
	k.deks[string(prefix)] = kh

	return ct, nil
}

func (k *KeyChain) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	prefix := ciphertext[:cryptofmt.NonRawPrefixSize]

	kh, ok := k.deks[string(prefix)]
	if !ok {
		return nil, errors.New("couldn't find matching DEK")
	}

	a, err := aead.New(kh)
	if err != nil {
		return nil, err
	}

	plaintext, err := a.Decrypt(ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
