package age

import (
	"reflect"
	"strings"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
)

func init() {
	keys.RegisterProvider(&Provider{})

	keyservice.RegisterKeyServiceAdapter(
		KeyTypeIdentifier,
		reflect.TypeOf(&keyservice.Key_AgeKey{}),
		keyservice.KeyServiceAdapter{
			ToKey: func(mk keys.MasterKey) *keyservice.Key {
				k := mk.(*MasterKey)
				return &keyservice.Key{
					KeyType: &keyservice.Key_AgeKey{
						AgeKey: &keyservice.AgeKey{
							Recipient: k.Recipient,
						},
					},
				}
			},
			Encrypt: func(key any, plaintext []byte) ([]byte, error) {
				k := key.(*keyservice.Key_AgeKey).AgeKey
				ageKey := MasterKey{Recipient: k.Recipient}
				err := ageKey.Encrypt(plaintext)
				return []byte(ageKey.EncryptedKey), err
			},
			Decrypt: func(key any, ciphertext []byte) ([]byte, error) {
				k := key.(*keyservice.Key_AgeKey).AgeKey
				ageKey := MasterKey{Recipient: k.Recipient}
				ageKey.EncryptedKey = string(ciphertext)
				plaintext, err := ageKey.Decrypt()
				return []byte(plaintext), err
			},
			ToString: func(key any) string {
				k := key.(*keyservice.Key_AgeKey).AgeKey
				return "Age key with recipient " + k.Recipient
			},
		},
	)

}

type Provider struct{}

func (p *Provider) Type() string {
	return "age"
}

func (p *Provider) MarshalKey(key keys.MasterKey) (map[string]any, error) {
	k, ok := key.(*MasterKey)
	if !ok {
		return nil, nil
	}
	return map[string]any{
		"recipient": k.Recipient,
		"enc":       k.EncryptedKey,
	}, nil
}

func (p *Provider) UnmarshalKey(data map[string]any) (keys.MasterKey, error) {
	var recipient, enc string
	if v, ok := data["recipient"].(string); ok {
		recipient = v
	}
	if v, ok := data["enc"].(string); ok {
		enc = v
	}

	return &MasterKey{
		Recipient:    recipient,
		EncryptedKey: enc,
	}, nil
}

func (p *Provider) KeysFromConfig(config any, opts keys.CreationOptions) ([]keys.MasterKey, error) {
	recipients, err := keys.ParseStringSlice(config, "age")
	if err != nil {
		return nil, err
	}
	if len(recipients) == 0 {
		return nil, nil
	}

	ageKeys, err := MasterKeysFromRecipients(strings.Join(recipients, ","))
	if err != nil {
		return nil, err
	}

	var res []keys.MasterKey
	for _, ak := range ageKeys {
		res = append(res, ak)
	}
	return res, nil
}

func (p *Provider) CLIConfig() []keys.ProviderFlag {
	return []keys.ProviderFlag{
		{
			Name:            "age, a",
			Usage:           "comma separated list of age recipients",
			EnvVar:          "SOPS_AGE_RECIPIENTS",
			IsKeyIdentifier: true,
		},
	}
}

func (p *Provider) MasterKeysFromCLI(c keys.FlagGetter, prefix string) ([]keys.MasterKey, error) {
	var masterKeys []keys.MasterKey
	flagName := prefix + "age"

	if prefix == "" {
		slices := c.StringSlice(flagName)
		if len(slices) > 0 {
			recs := strings.Join(slices, ",")
			ageKeys, err := MasterKeysFromRecipients(recs)
			if err != nil {
				return nil, err
			}
			for _, k := range ageKeys {
				masterKeys = append(masterKeys, k)
			}
			return masterKeys, nil
		}
	}

	recs := c.String(flagName)
	if recs == "" {
		return masterKeys, nil
	}
	ageKeys, err := MasterKeysFromRecipients(recs)
	if err != nil {
		return nil, err
	}
	for _, k := range ageKeys {
		masterKeys = append(masterKeys, k)
	}
	return masterKeys, nil
}
