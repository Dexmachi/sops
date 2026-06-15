package keyservice

import (
	"fmt"
	"reflect"

	"github.com/getsops/sops/v3/keys"
)

type KeyServiceAdapter struct {
	ToKey    func(keys.MasterKey) *Key
	Encrypt  func(key any, plaintext []byte) ([]byte, error)
	Decrypt  func(key any, ciphertext []byte) ([]byte, error)
	ToString func(key any) string
}

var (
	masterKeyToAdapter = make(map[string]KeyServiceAdapter)
	protoTypeToAdapter = make(map[reflect.Type]KeyServiceAdapter)
)

func RegisterKeyServiceAdapter(
	providerType string,
	protoType reflect.Type,
	adapter KeyServiceAdapter,
) {
	masterKeyToAdapter[providerType] = adapter
	protoTypeToAdapter[protoType] = adapter
}

func KeyFromMasterKey(mk keys.MasterKey) Key {
	adapter, ok := masterKeyToAdapter[mk.TypeToIdentifier()]
	if !ok {
		panic(fmt.Sprintf("Tried to convert unknown MasterKey type %T to keyservice.Key", mk))
	}
	return *adapter.ToKey(mk)
}
