package kms

import (
	"sync"
	"sync/atomic"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
)

const (
	// 2^21 for a 1/2^80 probability of collision of nonces.
	// https://en.wikipedia.org/wiki/Birthday_problem
	collisionTolerance = 2097152
)

type KeyChain struct {
	counter   uint32
	rotateMtx sync.Mutex

	kek *keyset.Handle
}

func New() (*KeyChain, error) {
	kek, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		return nil, err
	}

	return &KeyChain{
		kek: kek,
	}, nil
}

func (k *KeyChain) incrementUsageCounter() {
	atomic.AddUint32(&k.counter, 1)
}

func (k *KeyChain) validToUse() bool {
	return k.counter < collisionTolerance
}

func (k *KeyChain) Rotate() error {
	k.rotateMtx.Lock()
	defer k.rotateMtx.Unlock()

	ksm := keyset.NewManagerFromHandle(k.kek)
	if err := ksm.Rotate(aead.AES128GCMKeyTemplate()); err != nil {
		return err
	}

	kek, err := ksm.Handle()
	if err != nil {
		return err
	}

	k.kek = kek

	return nil
}
