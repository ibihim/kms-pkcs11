package pkcs11

import (
	"errors"

	"github.com/google/tink/go/tink"
	cryptoki "github.com/miekg/pkcs11"
)

type RSA struct {
	token *Token

	privKey   cryptoki.ObjectHandle
	pubKey    cryptoki.ObjectHandle
	mechanism []*cryptoki.Mechanism
}

var _ (tink.AEAD) = (*RSA)(nil)

func New() (*RSA, error) {
	t, err := NewToken()
	if err != nil {
		return nil, err
	}

	params := cryptoki.NewOAEPParams(
		cryptoki.CKM_SHA_1,
		cryptoki.CKG_MGF1_SHA1,
		cryptoki.CKZ_DATA_SPECIFIED,
		nil,
	)

	mech := []*cryptoki.Mechanism{
		cryptoki.NewMechanism(cryptoki.CKM_RSA_PKCS_OAEP, params),
	}

	return &RSA{
		token:     t,
		mechanism: mech,
	}, nil
}

func (r *RSA) encrypt(plaintext []byte) ([]byte, error) {
	return r.token.Encrypt(r.mechanism, r.pubKey, plaintext)
}

func (r *RSA) Encrypt(plaintext, _ []byte) ([]byte, error) {
	_, err := r.token.Open()
	defer r.token.Close()
	if err != nil {
		return nil, err
	}

	if r.pubKey != 0 {
		return r.encrypt(plaintext)
	}

	pub, priv, err := r.token.GetRSA()
	if err != nil {
		return nil, err
	}

	r.pubKey = pub
	r.privKey = priv

	return r.encrypt(plaintext)
}

func (r *RSA) decrypt(ciphertext []byte) ([]byte, error) {
	return r.token.Decrypt(r.mechanism, r.privKey, ciphertext)
}

func (r *RSA) Decrypt(ciphertext, _ []byte) ([]byte, error) {
	_, err := r.token.Open()
	defer r.token.Close()
	if err != nil {
		return nil, err
	}

	if r.privKey == 0 {
		return nil, errors.New("no private key found")
	}

	return r.decrypt(ciphertext)
}
