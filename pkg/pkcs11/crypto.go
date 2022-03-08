package pkcs11

import (
	"errors"

	cryptoki "github.com/miekg/pkcs11"
)

func (t *Token) Encrypt(
	mech []*cryptoki.Mechanism,
	key cryptoki.ObjectHandle,
	plaintext []byte,
) ([]byte, error) {
	if err := t.ctx.EncryptInit(t.session, mech, key); err != nil {
		return nil, err
	}

	ct, err := t.ctx.Encrypt(t.session, plaintext)
	if err != nil {
		return nil, err
	}

	return ct, nil
}

func (t *Token) Decrypt(
	mech []*cryptoki.Mechanism,
	key cryptoki.ObjectHandle,
	ciphertext []byte,
) ([]byte, error) {
	if err := t.ctx.DecryptInit(t.session, mech, key); err != nil {
		return nil, err
	}

	pt, err := t.ctx.Decrypt(t.session, ciphertext)
	if err != nil {
		return nil, err
	}

	return pt, nil
}

func (t *Token) GetRSA() (cryptoki.ObjectHandle, cryptoki.ObjectHandle, error) {
	return getRSA(t.ctx, t.session)
}

func getRSA(p *cryptoki.Ctx, sh cryptoki.SessionHandle) (cryptoki.ObjectHandle, cryptoki.ObjectHandle, error) {
	pub, err := findObject(p, sh, cryptoki.CKO_PUBLIC_KEY, "paramstest")
	if err != nil && !errors.Is(err, notFound) {
		return pub, 0, err
	}

	priv, err := findObject(p, sh, cryptoki.CKO_PUBLIC_KEY, "paramstest")
	if err != nil && !errors.Is(err, notFound) {
		return pub, priv, err
	}

	if errors.Is(err, notFound) {
		pub, priv, err = generateRSAKeyPair(p, sh, "paramstest", false)
		if err != nil {
			return pub, priv, err
		}
	}
	return pub, priv, nil
}

var (
	notFound error = errors.New("nothing found")
)

func findObject(p *cryptoki.Ctx, sh cryptoki.SessionHandle, class uint, label string) (cryptoki.ObjectHandle, error) {
	template := []*cryptoki.Attribute{
		cryptoki.NewAttribute(cryptoki.CKA_CLASS, class),
		cryptoki.NewAttribute(cryptoki.CKA_LABEL, label),
	}
	if err := p.FindObjectsInit(sh, template); err != nil {
		return 0, err
	}

	obj, _, err := p.FindObjects(sh, 1)
	if err != nil {
		return 0, err
	}

	if err := p.FindObjectsFinal(sh); err != nil {
		return 0, err
	}

	if len(obj) == 0 {
		return 0, notFound
	}

	return obj[0], nil
}

func generateRSAKeyPair(
	p *cryptoki.Ctx,
	sh cryptoki.SessionHandle,
	tokenLabel string,
	tokenPersistent bool,
) (
	cryptoki.ObjectHandle,
	cryptoki.ObjectHandle,
	error,
) {
	publicKeyTemplate := []*cryptoki.Attribute{
		cryptoki.NewAttribute(cryptoki.CKA_CLASS, cryptoki.CKO_PUBLIC_KEY),
		cryptoki.NewAttribute(cryptoki.CKA_KEY_TYPE, cryptoki.CKK_RSA),
		cryptoki.NewAttribute(cryptoki.CKA_TOKEN, tokenPersistent),
		cryptoki.NewAttribute(cryptoki.CKA_VERIFY, true),
		cryptoki.NewAttribute(cryptoki.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		cryptoki.NewAttribute(cryptoki.CKA_MODULUS_BITS, 2048),
		cryptoki.NewAttribute(cryptoki.CKA_LABEL, tokenLabel),
	}

	privateKeyTemplate := []*cryptoki.Attribute{
		cryptoki.NewAttribute(cryptoki.CKA_TOKEN, tokenPersistent),
		cryptoki.NewAttribute(cryptoki.CKA_SIGN, true),
		cryptoki.NewAttribute(cryptoki.CKA_LABEL, tokenLabel),
		cryptoki.NewAttribute(cryptoki.CKA_SENSITIVE, true),
		cryptoki.NewAttribute(cryptoki.CKA_EXTRACTABLE, true),
	}
	pbk, pvk, err := p.GenerateKeyPair(sh,
		[]*cryptoki.Mechanism{cryptoki.NewMechanism(cryptoki.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return 0, 0, err
	}

	return pbk, pvk, nil
}
