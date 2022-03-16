package client

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	api "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

type Client struct {
	address string

	cnn *grpc.ClientConn
}

func New(address string) *Client {
	return &Client{
		address: address,
	}
}

func (c *Client) open() (api.KeyManagementServiceClient, error) {
	cnn, err := grpc.Dial(
		c.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		return nil, err
	}

	c.cnn = cnn

	return api.NewKeyManagementServiceClient(cnn), nil
}

func dialer(ctx context.Context, addr string) (net.Conn, error) {
	return net.Dial("unix", addr)
}

func (c *Client) close() error {
	return c.cnn.Close()
}

func (c *Client) Decrypt(ctx context.Context, ct []byte) ([]byte, error) {
	service, err := c.open()
	if err != nil {
		return nil, err
	}
	defer c.close()

	res, err := service.Decrypt(ctx, &api.DecryptRequest{
		Version: "v1beta1",
		Cipher:  ct,
	})
	if err != nil {
		return nil, err
	}

	return res.Plain, nil
}

func (c *Client) Encrypt(ctx context.Context, pt []byte) ([]byte, error) {
	service, err := c.open()
	if err != nil {
		return nil, err
	}
	defer c.close()

	res, err := service.Encrypt(ctx, &api.EncryptRequest{
		Version: "v1beta1",
		Plain:   pt,
	})
	if err != nil {
		return nil, err
	}

	return res.Cipher, nil
}
