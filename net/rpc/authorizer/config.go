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
	AllowedNodePeerIds    map[string]struct{}
	AllowedAccountpubKeys pubKeys
}

type rawConfig struct {
	Enabled               bool
	AllowedAccountpubKeys []string `yaml:"allowed_accounts"`
	AllowedNodePeerIds    []string `yaml:"allowed_node_peers"`
}

func (c *Config) UnmarshalYAML(node *yaml.Node) error {

	var raw rawConfig

	if err := node.Decode(&raw); err != nil {
		return err
	}

	if !raw.Enabled {
		c.AllowedNodePeerIds = nil
		c.AllowedAccountpubKeys = nil

		return nil
	}

	c.AllowedAccountpubKeys = make(pubKeys)
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

	c.AllowedNodePeerIds = make(peerIds)
	for _, p := range raw.AllowedNodePeerIds {
		c.AllowedNodePeerIds[p] = struct{}{}
	}

	return nil
}
