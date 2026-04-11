package config

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/packet"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type SetConfig struct {
	Sets []Set `yaml:"packets,omitempty"`
}

func (sc *SetConfig) Validate() error {
	return validator.ValidateStructFields(sc)
}

type Set struct {
	Name    string   `yaml:"name,omitempty"`
	Type    string   `yaml:"type,omitempty"`
	Members []string `yaml:"members,omitempty"`
}

func SetsFromFile(file string) ([]*packet.Packet, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var sc SetConfig
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return nil, err
	}
	if err := sc.Validate(); err != nil {
		return nil, err
	}
	pkts := make([]*packet.Packet, 0, len(pc.Packets))
	for _, p := range pc.Packets {
		pkts = append(pkts, p.ToPacket())
	}
	return pkts, nil
}
