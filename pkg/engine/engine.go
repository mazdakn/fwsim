package engine

import (
	"fmt"
	"net"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/traffic"
	"github.com/sirupsen/logrus"
)

type Engine struct {
	config *Config

	rules []*model.Rule
}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) ConfigFromFile(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return err
	}
	if err := conf.Validate(); err != nil {
		return err
	}
	e.config = &conf
	return nil
}

func (e *Engine) Run() error {
	err := e.loadRules()
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	e.Validate()
	return nil
}

func (e *Engine) LoadRules() error {
	return e.loadRules()
}

func (e *Engine) loadRules() error {
	var err error
	for _, r := range e.config.Rules {
		rule := model.NewRule()

		rule.Protocol = r.Protocol
		rule.SrcPort = r.SrcPort
		rule.DstPort = r.DstPort

		rule.Action, err = model.ParseAction(r.Action)
		if err != nil {
			return fmt.Errorf("invalid action %s", rule.Action)
		}

		if r.SrcNet != "" {
			_, ipnet, err := net.ParseCIDR(r.SrcNet)
			if err != nil {
				return fmt.Errorf("invalid source net %s: %w", r.SrcNet, err)
			}
			rule.SrcNet = ipnet
		}

		if r.DstNet != "" {
			_, ipnet, err := net.ParseCIDR(r.DstNet)
			if err != nil {
				return fmt.Errorf("invalid destination net %s: %w", r.DstNet, err)
			}
			rule.DstNet = ipnet
		}

		e.rules = append(e.rules, rule)
	}
	return nil
}

func (e *Engine) Match(pkt *traffic.Packet) (int, *model.Rule) {
	logrus.Debugf("Matching packet %+v", pkt)
	for i, r := range e.rules {
		if r.Match(pkt) {
			logrus.Debugf("Rule %+v matched", r)
			return i, r
		}
	}
	logrus.Debug("No rule matched")
	return -1, nil
}

func packetFromExpectation(e *Expectation) *traffic.Packet {
	return traffic.NewPacket(
		traffic.WithProto(e.Packet.Proto),
		traffic.WithSrcPort(e.Packet.SrcPort),
		traffic.WithDstPort(e.Packet.DstPort),
		traffic.WithSrcAddr(e.Packet.SrcAddr),
		traffic.WithDstAddr(e.Packet.DstAddr),
	)
}
