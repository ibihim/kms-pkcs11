package kms

import (
	"bytes"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
)

func (k *KeyChain) decryptDEK(encDEK []byte) (*keyset.Handle, error) {
	a, err := aead.New(k.kek)
	if err != nil {
		return nil, err
	}

	dek, err := keyset.Read(
		keyset.NewBinaryReader(bytes.NewBuffer(encDEK)),
		a,
	)
	if err != nil {
		return nil, err
	}

	return dek, nil
}

func (k *KeyChain) encryptDEK(dek *keyset.Handle) ([]byte, error) {
	a, err := aead.New(k.kek)
	if err != nil {
		return nil, err
	}

	var dekBuf bytes.Buffer
	if err := dek.Write(keyset.NewBinaryWriter(&dekBuf), a); err != nil {
		return nil, err
	}

	return dekBuf.Bytes(), nil
}
