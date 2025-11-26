package traffic

import "sync"

// Generator manages packet generation and distribution through a channel.
type Generator struct {
	packets []*Packet
	channel chan *Packet
	mu      sync.RWMutex
}

// NewGenerator creates a new Generator with a buffered channel of the specified size.
func NewGenerator(bufferSize int) *Generator {
	return &Generator{
		packets: make([]*Packet, 0),
		channel: make(chan *Packet, bufferSize),
	}
}

// Register adds a packet to the generator's collection of packets.
func (g *Generator) Register(packet *Packet) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.packets = append(g.packets, packet)
}

// Send sends a packet to the buffered channel.
// Returns true if the packet was sent, false if the channel is full.
func (g *Generator) Send(packet *Packet) bool {
	select {
	case g.channel <- packet:
		return true
	default:
		return false
	}
}

// Channel returns the packet channel for receiving packets.
func (g *Generator) Channel() <-chan *Packet {
	return g.channel
}

// Packets returns a copy of all registered packets.
func (g *Generator) Packets() []*Packet {
	g.mu.RLock()
	defer g.mu.RUnlock()
	packets := make([]*Packet, len(g.packets))
	copy(packets, g.packets)
	return packets
}

// Close closes the packet channel.
func (g *Generator) Close() {
	close(g.channel)
}
