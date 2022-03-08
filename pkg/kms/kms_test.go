package kms_test

import (
	"bytes"
	"testing"

	"github.com/ibihim/kms-pkcs11/pkg/kms"
)

func identityBytes(b []byte) func() []byte {
	return func() []byte { return b }
}

func identityKeyChain(kc *kms.KeyChain, err error) func() (*kms.KeyChain, error) {
	return func() (*kms.KeyChain, error) { return kc, err }
}

func TestKEK(t *testing.T) {
	for _, tt := range []struct {
		name          string
		keyChain      func() (*kms.KeyChain, error)
		aad           func() []byte
		expectedError bool
	}{
		{
			name:          "should be able to encrypt and decrypt without authenticated additional data",
			keyChain:      identityKeyChain(kms.New(nil)),
			aad:           identityBytes([]byte("")),
			expectedError: false,
		},

		{
			name:          "should be able to encrypt and decrypt with authenticated additional data",
			keyChain:      identityKeyChain(kms.New(nil)),
			aad:           identityBytes([]byte("kek lives only in memory, beware")),
			expectedError: false,
		},

		{
			name:     "should not be able to decrypt without proper authenticated additional data",
			keyChain: identityKeyChain(kms.New(nil)),
			aad: func() func() []byte {
				var called bool

				encryptionAAD := []byte("kek lives only in memory, beware")
				decryptionAAD := []byte("")

				return func() []byte {
					if called {
						return decryptionAAD
					}

					called = true
					return encryptionAAD
				}
			}(),
			expectedError: true,
		},

		{
			name: "should not be able to decrypt with another key",
			keyChain: func() func() (*kms.KeyChain, error) {
				var called bool

				encryptionKey, err := kms.New(nil)
				if err != nil {
					return func() (*kms.KeyChain, error) { return nil, err }
				}
				decryptionKey, err := kms.New(nil)
				if err != nil {
					return func() (*kms.KeyChain, error) { return nil, err }
				}

				return func() (*kms.KeyChain, error) {
					if called {
						return decryptionKey, nil
					}

					called = true
					return encryptionKey, nil
				}
			}(),
			aad:           identityBytes([]byte("")),
			expectedError: true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			encryptKeyChain, err := tt.keyChain()
			if err != nil {
				t.Fatal(err)
			}

			msg := []byte("hello world")

			ed, err := encryptKeyChain.Encrypt(msg, tt.aad())
			if err != nil {
				t.Fatal(err)
			}

			decryptKeyChain, err := tt.keyChain()
			if err != nil {
				t.Fatal(err)
			}

			pt, err := decryptKeyChain.Decrypt(ed, tt.aad())
			if (err != nil) != tt.expectedError {
				t.Fatal(err)
			}

			if !bytes.Equal(msg, pt) && !tt.expectedError {
				t.Errorf(
					"want: '%s',\nhave: '%s'",
					string(msg),
					string(pt),
				)
			}
		})
	}
}
