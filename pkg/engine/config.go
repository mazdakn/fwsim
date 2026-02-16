package engine

import (
	"github.com/mazdakn/fwsim/internal/traffic"
	"github.com/mazdakn/fwsim/pkg/engine/config"
)

type Config struct {
	Rules        []config.Rule `yaml:"rules,omitempty"`
	Expectations []Expectation `yaml:"expectations,omitempty"`
}

func (c *Config) ToPolicyRules() ([]config.Rule, error) {
	// Rules are already in the correct format and validated during YAML unmarshaling
	// in Rule.UnmarshalYAML, so we just return them directly
	return c.Rules, nil
}

type Expectation struct {
	Result string          `yaml:"result,omitempty"`
	Packet *traffic.Packet `yaml:"packet,omitempty"`
}
