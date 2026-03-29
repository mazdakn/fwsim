package engine

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/model/packet"
)

type Engine struct {
	config *Config

	table *model.Table
}

func New() *Engine {
	return &Engine{
		table: model.NewTable("main", model.Drop),
	}
}

func (e *Engine) Run() error {
	err := e.LoadRules()
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	e.Validate()
	return nil
}

func (e *Engine) Match(pkt *packet.Packet) model.Result {
	return e.table.Match(pkt)
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

func (e *Engine) LoadRules() error {
	for _, r := range e.config.Rules {
		rule, err := r.ToRule()
		if err != nil {
			return err
		}
		e.table.AddRule(rule)
	}

	action, err := model.ParseAction(e.config.DefaultAction)
	if err != nil {
		return fmt.Errorf("invalid default action %s: %w", e.config.DefaultAction, err)
	}
	e.table.DefaultAction.Action = action

	return nil
}

func (e *Engine) PacketsFromFile(file string) ([]*packet.Packet, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var conf PacketsConfig
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	pkts := make([]*packet.Packet, 0, len(conf.Packets))
	for _, p := range conf.Packets {
		pkts = append(pkts, p.ToPacket())
	}
	return pkts, nil
}
