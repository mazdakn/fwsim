package config

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/packet"
	"github.com/mazdakn/fwsim/pkg/validator"
)

type PacketsConfig struct {
	Packets []packet.PacketConfig `yaml:"packets,omitempty"`
}

func (pc *PacketsConfig) Validate() error {
	return validator.ValidateStructFields(pc)
}

func PacketsFromFile(file string) ([]*packet.Packet, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var pc PacketsConfig
	if err := yaml.Unmarshal(data, &pc); err != nil {
		return nil, err
	}
	if err := pc.Validate(); err != nil {
		return nil, err
	}
	pkts := make([]*packet.Packet, 0, len(pc.Packets))
	for _, p := range pc.Packets {
		pkts = append(pkts, p.ToPacket())
	}
	return pkts, nil
}
