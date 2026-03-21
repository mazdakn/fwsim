package engine

import (
	"fmt"
	"net"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/traffic"
)

type Engine struct {
	config *Config

	table *model.Table
}

func New() *Engine {
	return &Engine{
		table: model.NewTable("main", model.Drop), // TODO: get default action directly from config.
	}
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

		e.table.Rules = append(e.table.Rules, rule)
	}

	action, err := model.ParseAction(e.config.DefaultAction)
	if err != nil {
		return fmt.Errorf("invalid default action %s: %w", e.config.DefaultAction, err)
	}
	e.table.DefaultAction = model.NewRule(model.WithAction(action))

	return nil
}

func (e *Engine) Match(pkt *traffic.Packet) model.Result {
	return e.table.Match(pkt)
}
