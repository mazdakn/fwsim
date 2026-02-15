package engine

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/traffic"
	"github.com/sirupsen/logrus"
)

type Engine struct {
	config *Config

	rules []model.Rule
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

func (e *Engine) Validate() {
	for index, exp := range e.config.Expectations {
		pkt, err := e.config.ToPacket(exp.Packet)
		if err != nil {
			logrus.WithError(err).Errorf("failed to parse packet: %#v - Skipping.", exp.Packet)
			continue
		}

		_, r := e.Match(pkt)
		expA := r.Action.String()
		expB := exp.Result

		if expA == expB {
			logrus.Infof("Expectation %d met", index)
		} else {
			logrus.Errorf("Expectation %d not met", index)
		}
	}
}

func (e *Engine) Match(pkt *traffic.Packet) (int, *model.Rule) {
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
