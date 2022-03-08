package pkcs11

import (
	"log"

	cryptoki "github.com/miekg/pkcs11"
)

type Token struct {
	ctx     *cryptoki.Ctx
	session cryptoki.SessionHandle

	getPIN func() (string, error)
}

func NewToken(configs ...func(t *Token) error) (*Token, error) {
	var t Token

	for _, config := range configs {
		if err := config(&t); err != nil {
			return nil, err
		}
	}

	if t.getPIN == nil {
		t.getPIN = readPIN
	}

	if t.ctx == nil {
		t.ctx = cryptoki.New("/usr/local/lib/softhsm/libsofthsm2.so")
	}

	return &t, nil
}

func WithLib(path string) func(t *Token) error {
	return func(t *Token) error {
		t.ctx = cryptoki.New(path)
		return nil
	}
}

func WithPIN(getPIN func() (string, error)) func(t *Token) error {
	return func(t *Token) error {
		t.getPIN = getPIN
		return nil
	}
}

// Close closes, even though it might not exist. Best effort as of now.
func (t *Token) Close() {
	if err := t.ctx.Logout(t.session); err != nil && t.session != 0 {
		log.Println(err)
		return
	}

	if err := t.ctx.CloseSession(t.session); err != nil && t.session != 0 {
		log.Println(err)
		return
	}

	if err := t.ctx.Finalize(); err != nil {
		log.Println(err)
		return
	}

	t.ctx.Destroy()
}

func (t *Token) Open() (cryptoki.SessionHandle, error) {
	pin, err := t.getPIN()
	if err != nil {
		return 0, err
	}

	return t.OpenWithPIN(pin)
}

func (t *Token) OpenWithPIN(pin string) (cryptoki.SessionHandle, error) {
	if err := t.ctx.Initialize(); err != nil {
		return 0, err
	}

	slots, err := t.ctx.GetSlotList( /*tokenPresent:*/ true)
	if err != nil {
		return 0, err
	}

	session, err := t.ctx.OpenSession(slots[0], cryptoki.CKF_SERIAL_SESSION|cryptoki.CKF_RW_SESSION)
	if err != nil {
		return 0, err
	}

	if err = t.ctx.Login(session, cryptoki.CKU_USER, pin); err != nil {
		return 0, err
	}

	return session, nil
}

func readPIN() (string, error) {
	// best effort :D
	return "1234", nil
}
