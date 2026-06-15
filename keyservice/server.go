package keyservice

import (
	"fmt"
	"reflect"

	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	Prompt bool
}

func (ks Server) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	if req.Key == nil || req.Key.KeyType == nil {
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	}

	adapter, ok := protoTypeToAdapter[reflect.TypeOf(req.Key.KeyType)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Unknown key type")
	}

	ciphertext, err := adapter.Encrypt(req.Key.KeyType, req.Plaintext)
	if err != nil {
		return nil, err
	}

	if ks.Prompt {
		err := ks.prompt(req.Key, "encrypt")
		if err != nil {
			return nil, err
		}
	}
	return &EncryptResponse{Ciphertext: ciphertext}, nil
}

func keyToString(key *Key) string {
	if key == nil || key.KeyType == nil {
		return "Unknown key type"
	}
	adapter, ok := protoTypeToAdapter[reflect.TypeOf(key.KeyType)]
	if !ok {
		return "Unknown key type"
	}
	return adapter.ToString(key.KeyType)
}

func (ks Server) prompt(key *Key, requestType string) error {
	keyString := keyToString(key)
	var response string
	for response != "y" && response != "n" {
		fmt.Printf("\nReceived %s request using %s. Respond to request? (y/n): ", requestType, keyString)
		_, err := fmt.Scanln(&response)
		if err != nil {
			return err
		}
	}
	if response == "n" {
		return status.Errorf(codes.PermissionDenied, "Request rejected by user")
	}
	return nil
}

func (ks Server) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	if req.Key == nil || req.Key.KeyType == nil {
		return nil, status.Errorf(codes.NotFound, "Must provide a key")
	}

	adapter, ok := protoTypeToAdapter[reflect.TypeOf(req.Key.KeyType)]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Unknown key type")
	}

	plaintext, err := adapter.Decrypt(req.Key.KeyType, req.Ciphertext)
	if err != nil {
		return nil, err
	}

	if ks.Prompt {
		err := ks.prompt(req.Key, "decrypt")
		if err != nil {
			return nil, err
		}
	}
	return &DecryptResponse{Plaintext: plaintext}, nil
}
