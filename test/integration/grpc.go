package grpc

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ibihim/kms-proxy/pkg/client"
	"github.com/ibihim/kms-proxy/pkg/server"
)

func TestEncryption(t *testing.T) {
	for _, tc := range [...]struct {
		name string
	}{
		{
			name: "happy case",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			address := "/tmp/unix.sock"
			go func() {
				if err := server.Run(address); err != nil {
					fmt.Printf("server run: %v\n", err)
				}
			}()

			time.Sleep(time.Second)

			c := client.New(address)

			ctx := context.Background()
			msg := []byte("hello world")

			ct, err := c.Encrypt(ctx, msg)
			if err != nil {
				t.Fatal(err)
			}

			fmt.Printf("encrypted text: %s", string(ct))

			pt, err := c.Decrypt(ctx, ct)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(msg, pt) {
				t.Errorf("have: %s, want:  %s", string(msg), string(pt))
			}
		})
	}
}
