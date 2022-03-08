package pkcs11_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestPKCS11(t *testing.T) {
	p := pkcs11.New("/usr/local/lib/softhsm/libsofthsm2.so")
	if err := p.Initialize(); err != nil {
		panic(err)
	}

	defer p.Destroy()
	defer func() {
		_ = p.Finalize()
	}()

	slots, err := p.GetSlotList( /*tokenPresent:*/ true)
	if err != nil {
		t.Fatal(err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = p.CloseSession(session)
	}()

	if err = p.Login(session, pkcs11.CKU_USER, "1234"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = p.Logout(session)
	}()

	pub, priv, err := getRSA(p, session)
	if err != nil {
		t.Fatal(err)
	}

	params := pkcs11.NewOAEPParams(
		pkcs11.CKM_SHA_1,
		pkcs11.CKG_MGF1_SHA1,
		pkcs11.CKZ_DATA_SPECIFIED,
		nil,
	)

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params),
	}
	if err := p.EncryptInit(session, mech, pub); err != nil {
		t.Fatal(err)
	}

	msg := "hi"
	ct, err := p.Encrypt(session, []byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf(
		"encrypted %s into %s\n",
		msg,
		base64.StdEncoding.EncodeToString(ct),
	)

	if err := p.DecryptInit(session, mech, priv); err != nil {
		t.Fatal(err)
	}
	pt, err := p.Decrypt(session, ct)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf(
		"decyprted %s into %s\n",
		base64.StdEncoding.EncodeToString(ct),
		pt,
	)
}

func getRSA(p *pkcs11.Ctx, sh pkcs11.SessionHandle) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	pub, err := findObject(p, sh, pkcs11.CKO_PUBLIC_KEY, "paramstest")
	if err != nil && !errors.Is(err, notFound) {
		return pub, 0, err
	}

	priv, err := findObject(p, sh, pkcs11.CKO_PUBLIC_KEY, "paramstest")
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

func findObject(p *pkcs11.Ctx, sh pkcs11.SessionHandle, class uint, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
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
	p *pkcs11.Ctx,
	sh pkcs11.SessionHandle,
	tokenLabel string,
	tokenPersistent bool,
) (
	pkcs11.ObjectHandle,
	pkcs11.ObjectHandle,
	error,
) {
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	pbk, pvk, err := p.GenerateKeyPair(sh,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return 0, 0, err
	}

	return pbk, pvk, nil
}
