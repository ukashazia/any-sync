package authorizer

import (
	"github.com/anyproto/any-sync/util/crypto"
	"gopkg.in/yaml.v3"
)

type ConfigGetter interface {
	GetAuthorizerConf() Config
}

type peerIds = map[string]struct{}
type pubKeys = map[[32]byte]crypto.PubKey
type Config struct {
	Enabled               bool
	AllowedAccountpubKeys pubKeys
}

type rawConfig struct {
	Enabled               bool
	AllowedAccountpubKeys []string `yaml:"allowed_accounts"`
}

func (c *Config) UnmarshalYAML(node *yaml.Node) error {

	var raw rawConfig

	if err := node.Decode(&raw); err != nil {
		return err
	}

	c.AllowedAccountpubKeys = make(pubKeys)

	if !raw.Enabled {
		return nil
	}

	for _, k := range raw.AllowedAccountpubKeys {
		bytes, err := crypto.DecodeBytesFromString(k)
		if err != nil {
			return err
		}

		pubKey, err := crypto.UnmarshalEd25519PublicKey(bytes)
		if err != nil {
			return err
		}

		c.AllowedAccountpubKeys[[32]byte(bytes)] = pubKey
	}

	return nil
}
