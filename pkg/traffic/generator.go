package traffic

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

type GeneratorOption func(*Generator)

func WithEgress(egress chan []Packet) GeneratorOption {
	return func(g *Generator) {
		g.egress = egress
	}
}

// Send all registered packets with this rate.
func WithRate(rate time.Duration) GeneratorOption {
	return func(g *Generator) {
		g.rate = rate
	}
}

type Generator struct {
	name    string
	rate    time.Duration
	packets []Packet
	egress  chan<- []Packet
	logCtx  *logrus.Entry
}

func NewGenerator(name string, opts ...GeneratorOption) *Generator {
	g := Generator{
		name:   name,
		rate:   time.Second * 1,
		logCtx: logrus.WithField("name", name),
	}
	for _, o := range opts {
		o(&g)
	}
	return &g
}

func (g *Generator) Register(pkt *Packet) {
	g.packets = append(g.packets, *pkt)
}

func (g *Generator) Flush() {
	g.packets = nil
}

func (g *Generator) Send() {
	g.logCtx.Debugf("Sending packets %+v", g.packets)
	g.egress <- g.packets
}

func (g *Generator) Start(ctx context.Context) {
	ticker := time.NewTicker(g.rate)
	go func() {
		for {
			select {
			case <-ctx.Done():
				g.logCtx.WithError(ctx.Err()).Debug("Context canceled")
				return
			case <-ticker.C:
				g.logCtx.Debugf("Triggering packet send")
				g.Send()
			}
		}
	}()
}
