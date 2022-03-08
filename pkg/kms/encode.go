package kms

import (
	"bytes"
	"encoding/gob"
)

type EncryptedData struct {
	Ciphertext   []byte
	EncryptedDEK []byte
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

// TODO combine decode and decrypt to not return []byte, []byte.
func decode(encryptedData []byte) ([]byte, []byte, error) {
	dec := gob.NewDecoder(bytes.NewBuffer(encryptedData))

	var ed EncryptedData
	if err := dec.Decode(&ed); err != nil {
		return nil, nil, err
	}

	return ed.EncryptedDEK, ed.Ciphertext, nil
}
