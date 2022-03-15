package server

import (
	"net"
	"os"

	"google.golang.org/grpc"

	api "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

func Run(address string) error {
	if err := os.RemoveAll(address); err != nil {
		return err
	}

	listen, err := net.Listen("unix", address)
	if err != nil {
		return err
	}
	defer listen.Close()

	grpcServer := grpc.NewServer()
	api.RegisterKeyManagementServiceServer(grpcServer, &server{})

	return grpcServer.Serve(listen)
}
