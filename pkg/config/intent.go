package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/firecore/match"
	"github.com/mazdakn/firecore/rule"
)

// Intent expresses a user's expectation about how a specific packet should be
// processed by the firewall rules.
type Intent struct {
	// Name is an optional human-readable label for the intent.
	Name string `yaml:"name,omitempty"`
	// Packet describes the packet to be matched (mandatory).
	Packet Packet `yaml:"packet"`
	// ExpectedVerdict is the verdict the user expects the packet to receive.
	// Supported values: Accept, Drop, Pass (case-insensitive).
	// Leave empty to skip verdict validation; when set, validation fails if the
	// actual verdict does not match.
	ExpectedVerdict string `yaml:"expected_verdict,omitempty"`
	// HitByRule is the name of the rule the user expects to match the packet.
	// Leave empty to skip rule validation.
	HitByRule string `yaml:"hit_by_rule,omitempty"`
}

// ToMatchContext converts the Intent into a MatchContext ready for use by the
// engine. The packet's name defaults to the intent name when not set
// explicitly.
func (i *Intent) ToMatchContext() (*match.MatchContext, error) {
	pkt := i.Packet.ToPacket()
	if pkt.Metadata.Name == "" && i.Name != "" {
		pkt.Metadata.Name = i.Name
	}

	opts := []match.MatchContextOption{}
	if i.ExpectedVerdict != "" {
		a, err := rule.ParseAction(i.ExpectedVerdict)
		if err != nil {
			return nil, fmt.Errorf("intent %q: invalid expected_verdict: %w", i.Name, err)
		}
		opts = append(opts, match.WithExpectedVerdict(a))
	}
	if i.HitByRule != "" {
		opts = append(opts, match.WithExpectedRule(i.HitByRule))
	}

	return match.New(pkt, opts...), nil
}

// IntentFromBytes parses a single Intent from YAML bytes.
func IntentFromBytes(data []byte) (*Intent, error) {
	var intent Intent
	if err := yaml.Unmarshal(data, &intent); err != nil {
		return nil, err
	}
	if err := intent.Packet.Validate(); err != nil {
		return nil, fmt.Errorf("intent %q: invalid packet: %w", intent.Name, err)
	}
	if intent.ExpectedVerdict != "" {
		if _, err := rule.ParseAction(intent.ExpectedVerdict); err != nil {
			return nil, fmt.Errorf("intent %q: invalid expected_verdict: %w", intent.Name, err)
		}
	}
	return &intent, nil
}

// IntentFromFile parses a single Intent from a YAML file.
func IntentFromFile(file string) (*Intent, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return IntentFromBytes(data)
}
