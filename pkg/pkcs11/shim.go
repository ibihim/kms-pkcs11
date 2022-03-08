package pkcs11

import "github.com/google/tink/go/tink"

type PKCS11 struct{}

var _ (tink.AEAD) = (*PKCS11)(nil)

func (p *PKCS11) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	return nil, nil
}

func (p *PKCS11) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	return nil, nil
}
