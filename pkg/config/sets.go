package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/validator"
)

// SetConfig is the top-level structure for a sets YAML file.
type SetConfig struct {
	Sets []Set `yaml:"sets,omitempty"`
}

func (sc *SetConfig) Validate() error {
	return validator.ValidateStructFields(sc)
}

// Set represents the YAML configuration for a named set of values.
type Set struct {
	Name    string   `yaml:"name,omitempty"`
	Type    string   `yaml:"type,omitempty"    validate:"isValidSetType"`
	Members []string `yaml:"members,omitempty"`
}

// ToSet converts a Set config into the appropriate set.Set implementation
// based on the Type field ("ip", "port", or "proto").
func (s *Set) ToSet() (set.Set, error) {
	var result set.Set
	switch s.Type {
	case "ip":
		result = set.NewIPSet()
	case "port":
		result = set.NewPortSet()
	case "proto":
		result = set.NewProtoSet()
	default:
		return nil, fmt.Errorf("unknown set type %q", s.Type)
	}
	for _, member := range s.Members {
		if err := result.Add(member); err != nil {
			return nil, fmt.Errorf("set %q: invalid member %q: %w", s.Name, member, err)
		}
	}
	return result, nil
}

// SetsFromBytes parses YAML bytes and returns a map of named set.Set values.
func SetsFromBytes(data []byte) (map[string]set.Set, error) {
	var sc SetConfig
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return nil, err
	}
	if err := sc.Validate(); err != nil {
		return nil, err
	}
	sets := make(map[string]set.Set, len(sc.Sets))
	for _, s := range sc.Sets {
		namedSet, err := s.ToSet()
		if err != nil {
			return nil, err
		}
		sets[s.Name] = namedSet
	}
	return sets, nil
}

// SetsFromFile reads a YAML file and returns a map of named set.Set values.
func SetsFromFile(file string) (map[string]set.Set, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return SetsFromBytes(data)
}
