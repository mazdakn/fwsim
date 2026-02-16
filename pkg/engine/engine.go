package engine

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/traffic"
	"github.com/mazdakn/fwsim/pkg/engine/config"
	"github.com/sirupsen/logrus"
)

type Engine struct {
	config *Config

	rules []config.Rule
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) LoadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	rules, err := cfg.ToPolicyRules()
	if err != nil {
		return err
	}

	e.rules = append(e.rules, rules...)
	e.config = &cfg
	return nil
}

func (e *Engine) Match(pkt *traffic.Packet) (int, *config.Rule) {
	logrus.Debugf("Matching packet %+v", pkt)
	for i, r := range e.rules {
		if r.Match(pkt) {
			logrus.Debugf("Rule %+v matched", r)
			return i, &r
		}
	}
	logrus.Debug("No rule matched")
	return -1, nil
}
