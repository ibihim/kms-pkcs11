package server

import (
	"context"
	"io"

	api "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"

	"github.com/ibihim/kms-proxy/pkg/kms"
)

type server struct {
	kek *kms.KeyChain

	store io.Writer
}

func New(store io.Writer) (*server, error) {
	kek, err := kms.New()
	if err != nil {
		return nil, err
	}

	return &server{
		kek: kek,
	}, nil
}

func (s *server) Version(ctx context.Context, req *api.VersionRequest) (*api.VersionResponse, error) {
	return &api.VersionResponse{
		Version:        "v1beta1",
		RuntimeName:    "kms-proxy",
		RuntimeVersion: "v0.0.0",
	}, nil
}

func (s *server) Decrypt(ctx context.Context, req *api.DecryptRequest) (*api.DecryptResponse, error) {
	pt, err := s.kek.Decrypt(req.Cipher)
	if err != nil {
		return nil, err
	}

	return &api.DecryptResponse{
		Plain: pt,
	}, nil
}

func (s *server) Encrypt(ctx context.Context, req *api.EncryptRequest) (*api.EncryptResponse, error) {
	ct, err := s.kek.Encrypt(req.Plain)
	if err != nil {
		return nil, err
	}

	return &api.EncryptResponse{
		Cipher: ct,
	}, nil
}
