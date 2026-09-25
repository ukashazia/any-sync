package authorizer

import (
	"github.com/anyproto/any-sync/util/crypto"
	"gopkg.in/yaml.v3"
)

type ConfigGetter interface {
	GetAuthorizerConf() Config
}

type pubKeys = map[[32]byte]struct{}
type Config struct {
	Enabled               bool
	AllowedAccountPubKeys pubKeys
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

	c.AllowedAccountPubKeys = make(pubKeys)

	if !raw.Enabled {
		c.Enabled = false
		return nil
	}

	c.Enabled = true
	for _, k := range raw.AllowedAccountpubKeys {
		bytes, err := crypto.DecodeBytesFromString(k)
		if err != nil {
			return err
		}

		_, err = crypto.UnmarshalEd25519PublicKey(bytes)
		if err != nil {
			return err
		}

		c.AllowedAccountPubKeys[[32]byte(bytes)] = struct{}{}
	}

	return nil
}
