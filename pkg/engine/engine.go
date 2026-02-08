package engine

import (
	"github.com/mazdakn/fwsim/pkg/policy"
	"github.com/sirupsen/logrus"
)

type Engine struct {
	config *Config

	store        *policy.Store
	expectations []Expectation
}

func New() *Engine {
	return &Engine{
		store: policy.NewStore(),
	}
}

func (e *Engine) Validate() {
	for index, exp := range e.config.Expectations {
		pkt, err := e.config.ToPacket(exp.Packet)
		if err != nil {
			logrus.WithError(err).Errorf("failed to parse packet: %#v - Skipping.", exp.Packet)
			continue
		}

		_, r := e.store.Match(pkt)
		expA := r.Action.String()
		expB := exp.Result

		if expA == expB {
			logrus.Infof("Expectation %d met", index)
		} else {
			logrus.Errorf("Expectation %d not met", index)
		}
	}
}

func (e *Engine) LoadConfig(path string) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	rules, err := cfg.ToPolicyRules()
	if err != nil {
		return err
	}
	for _, r := range rules {
		e.store.AddRule(r)
	}

	e.config = cfg
	return nil
}
