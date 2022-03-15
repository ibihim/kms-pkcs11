package kms

import (
	"io"
	"sync"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

type KeyChain struct {
	counter   uint32
	rotateMtx sync.Mutex

	kek  *keyset.Handle
	deks map[string]*keyset.Handle
}

func New() (*KeyChain, error) {
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

func Read(r io.Reader, rootKey tink.AEAD) error {
	/* TODO */
	return nil
}

func (k *KeyChain) Write(w io.Writer, rootKey tink.AEAD) error {
	/* TODO */
	return nil
}

func ReadKEK(r io.Reader, rootKey tink.AEAD) (*keyset.Handle, error) {
	br := keyset.NewBinaryReader(r)

	kek, err := keyset.Read(br, rootKey)
	if err != nil {
		return nil, err
	}

	return kek, nil
}

func (k *KeyChain) WriteKEK(w io.Writer, rootKey tink.AEAD) error {
	bw := keyset.NewBinaryWriter(w)

	if err := k.kek.Write(bw, rootKey); err != nil {
		return err
	}

	return nil
}
