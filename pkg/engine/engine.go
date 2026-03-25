package engine

import (
	"fmt"
	"net"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/internal/model"
	"github.com/mazdakn/fwsim/internal/set"
	"github.com/mazdakn/fwsim/internal/traffic"
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

func (e *Engine) Match(pkt *traffic.Packet) model.Result {
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
	var err error
	for _, r := range e.config.Rules {
		rule := model.NewRule()

		rule.Name = r.Name

		if len(r.Protocol) > 0 {
			rule.Proto = set.NewProtoSet()
			for _, proto := range r.Protocol {
				rule.Proto.Add(proto)
			}
		}

		if len(r.SrcPort) > 0 {
			rule.SrcPort = set.NewPortSet()
			for _, port := range r.SrcPort {
				rule.SrcPort.Add(port)
			}
		}
		if len(r.DstPort) > 0 {
			rule.DstPort = set.NewPortSet()
			for _, port := range r.DstPort {
				rule.DstPort.Add(port)
			}
		}

		rule.Action, err = model.ParseAction(r.Action)
		if err != nil {
			return fmt.Errorf("invalid action %s", rule.Action)
		}

		if len(r.SrcNet) > 0 {
			srcNets := make([]*net.IPNet, 0, len(r.SrcNet))
			for _, srcNet := range r.SrcNet {
				_, ipnet, err := net.ParseCIDR(srcNet)
				if err != nil {
					return fmt.Errorf("invalid source net %s: %w", srcNet, err)
				}
				srcNets = append(srcNets, ipnet)
			}
			rule.SrcNet = set.NewIPSet()
			for _, ipnet := range srcNets {
				rule.SrcNet.Add(ipnet)
			}
		}

		if len(r.DstNet) > 0 {
			dstNets := make([]*net.IPNet, 0, len(r.DstNet))
			for _, dstNet := range r.DstNet {
				_, ipnet, err := net.ParseCIDR(dstNet)
				if err != nil {
					return fmt.Errorf("invalid destination net %s: %w", dstNet, err)
				}
				dstNets = append(dstNets, ipnet)
			}
			rule.DstNet = set.NewIPSet()
			for _, ipnet := range dstNets {
				rule.DstNet.Add(ipnet)
			}
		}

		e.table.Rules = append(e.table.Rules, rule)
	}

	action, err := model.ParseAction(e.config.DefaultAction)
	if err != nil {
		return fmt.Errorf("invalid default action %s: %w", e.config.DefaultAction, err)
	}
	e.table.DefaultAction.Action = action

	return nil
}

func (e *Engine) PacketsFromFile(file string) ([]*traffic.Packet, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var conf PacketsConfig
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	pkts := make([]*traffic.Packet, 0, len(conf.Packets))
	for _, p := range conf.Packets {
		pkt := traffic.NewPacket(
			traffic.WithName(p.Name),
			traffic.WithSrcAddr(p.SrcAddr),
			traffic.WithDstAddr(p.DstAddr),
			traffic.WithProto(p.Proto),
			traffic.WithSrcPort(p.SrcPort),
			traffic.WithDstPort(p.DstPort),
		)
		pkts = append(pkts, pkt)
	}
	return pkts, nil
}
