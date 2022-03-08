package kms

import (
	"io"
	"sync"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
)

type KeyChain struct {
	counter   uint32
	rotateMtx sync.Mutex

	kek  *keyset.Handle
	deks map[string]*keyset.Handle
}

func New(_ io.Writer) (*KeyChain, error) {
	kek, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, err
	}

	deks := make(map[string]*keyset.Handle)

	return &KeyChain{
		kek:  kek,
		deks: deks,
	}, nil
}

func (k *KeyChain) Read(rootKey []byte) error {

	return nil
}

func (k *KeyChain) Write(w io.Writer, rootKey []byte) error {
	/*
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
	*/

	return nil
}
