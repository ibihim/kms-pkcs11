package kms

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/cryptofmt"
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

	kek  *keyset.Handle
	deks map[string]*keyset.Handle
}

func (k *KeyChain) incrementUsageCounter() {
	atomic.AddUint32(&k.counter, 1)
}

func (k *KeyChain) validToUse() bool {
	return k.counter < collisionTolerance
}

type EncryptedData struct {
	Ciphertext   []byte
	EncryptedDEK []byte
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

func encode(dek, ct []byte) ([]byte, error) {
	var edBuf bytes.Buffer
	enc := gob.NewEncoder(&edBuf)

	if err := enc.Encode(EncryptedData{
		EncryptedDEK: dek,
		Ciphertext:   ct,
	}); err != nil {
		return nil, err
	}

	return edBuf.Bytes(), nil
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

// TODO combine decode and decrypt to not return []byte, []byte.
func decode(encryptedData []byte) ([]byte, []byte, error) {
	dec := gob.NewDecoder(bytes.NewBuffer(encryptedData))

	var ed EncryptedData
	if err := dec.Decode(&ed); err != nil {
		return nil, nil, err
	}

	return ed.EncryptedDEK, ed.Ciphertext, nil
}

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
