package engine

import (
	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/traffic"
)

type Config struct {
	Rules        []model.Rule  `yaml:"rules,omitempty"`
	Expectations []Expectation `yaml:"expectations,omitempty"`
}

func (c *Config) ToPolicyRules() ([]model.Rule, error) {
	// Rules are already in the correct format and validated during YAML unmarshaling
	// in Rule.UnmarshalYAML, so we just return them directly
	return c.Rules, nil
}

type Expectation struct {
	Result string          `yaml:"result,omitempty"`
	Packet *traffic.Packet `yaml:"packet,omitempty"`
}
