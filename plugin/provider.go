package plugin

import (
	"time"

	"encoding/json"
	"fmt"
	"reflect"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
)

func init() {
	keys.RegisterProvider(&Provider{})

	keyservice.RegisterKeyServiceAdapter(
		KeyTypeIdentifier,
		reflect.TypeOf(&keyservice.Key_PluginKey{}),
		keyservice.KeyServiceAdapter{
			ToKey: func(mk keys.MasterKey) *keyservice.Key {
				k := mk.(*MasterKey)
				configBytes, _ := json.Marshal(k.PluginConfig)
				return &keyservice.Key{
					KeyType: &keyservice.Key_PluginKey{
						PluginKey: &keyservice.PluginKey{
							BinaryName: k.BinaryName,
							InstanceId: k.InstanceID,
							Config:     string(configBytes),
							Timeout:    k.Timeout,
						},
					},
				}
			},
			Encrypt: func(key any, plaintext []byte) ([]byte, error) {
				k := key.(*keyservice.Key_PluginKey).PluginKey
				var config map[string]any
				_ = json.Unmarshal([]byte(k.Config), &config)
				pluginKey := NewMasterKey(k.BinaryName, config, k.Timeout, k.InstanceId)
				err := pluginKey.Encrypt(plaintext)
				return []byte(pluginKey.EncryptedKey), err
			},
			Decrypt: func(key any, ciphertext []byte) ([]byte, error) {
				k := key.(*keyservice.Key_PluginKey).PluginKey
				var config map[string]any
				_ = json.Unmarshal([]byte(k.Config), &config)
				pluginKey := NewMasterKey(k.BinaryName, config, k.Timeout, k.InstanceId)
				pluginKey.EncryptedKey = string(ciphertext)
				plaintext, err := pluginKey.Decrypt()
				return plaintext, err
			},
			ToString: func(key any) string {
				k := key.(*keyservice.Key_PluginKey).PluginKey
				return fmt.Sprintf("Plugin key with binary %s and instance %s", k.BinaryName, k.InstanceId)
			},
		},
	)

}

type Provider struct{}

func (p *Provider) Type() string {
	return "plugins"
}

func (p *Provider) MarshalKey(key keys.MasterKey) (map[string]any, error) {
	k, ok := key.(*MasterKey)
	if !ok {
		return nil, nil
	}
	return map[string]any{
		"binary_name": k.BinaryName,
		"instance_id": k.InstanceID,
		"config":      k.PluginConfig,
		"enc":         k.EncryptedKey,
		"created_at":  k.CreationDate.Format(time.RFC3339),
		"timeout":     k.Timeout,
	}, nil
}

func (p *Provider) UnmarshalKey(data map[string]any) (keys.MasterKey, error) {
	var binaryName, instanceID, enc, timeout, createdAtStr string
	if v, ok := data["binary_name"].(string); ok {
		binaryName = v
	}
	if v, ok := data["instance_id"].(string); ok {
		instanceID = v
	}
	if v, ok := data["enc"].(string); ok {
		enc = v
	}
	if v, ok := data["timeout"].(string); ok {
		timeout = v
	}
	if v, ok := data["created_at"].(string); ok {
		createdAtStr = v
	}

	var config map[string]any
	if v, ok := data["config"].(map[string]any); ok {
		config = v
	} else if v, ok := data["config"].(map[interface{}]interface{}); ok {
		config = make(map[string]any)
		for k, val := range v {
			if s, ok := k.(string); ok {
				config[s] = val
			}
		}
	}

	createdAt, err := time.Parse(time.RFC3339, createdAtStr)
	if err != nil {
		return nil, err
	}
	return &MasterKey{
		BinaryName:   binaryName,
		InstanceID:   instanceID,
		PluginConfig: config,
		EncryptedKey: enc,
		CreationDate: createdAt,
		Timeout:      timeout,
	}, nil
}

func (p *Provider) KeysFromConfig(config any, opts keys.CreationOptions) ([]keys.MasterKey, error) {
	maps, ok := config.([]interface{})
	if !ok {
		return nil, nil
	}

	var globalTimeout string
	if opts.GlobalConfig != nil {
		if t, ok := opts.GlobalConfig["timeout"].(string); ok {
			globalTimeout = t
		}
	}

	var res []keys.MasterKey
	for _, item := range maps {
		m, ok := item.(map[string]interface{})
		if !ok {
			// yaml.v3 might decode to map[string]interface{}
			continue
		}
		var binaryName, instanceID, timeout string
		if v, ok := m["binary_name"].(string); ok {
			binaryName = v
		}
		if v, ok := m["instance_id"].(string); ok {
			instanceID = v
		}
		if v, ok := m["timeout"].(string); ok {
			timeout = v
		}

		if timeout == "" {
			timeout = globalTimeout
		}

		var pluginConfig map[string]interface{}
		if v, ok := m["config"].(map[string]interface{}); ok {
			pluginConfig = v
		}
		res = append(res, NewMasterKey(binaryName, pluginConfig, timeout, instanceID))
	}
	return res, nil
}
