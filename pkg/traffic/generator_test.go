package traffic

import (
	"sync"
	"testing"

	. "github.com/onsi/gomega"
)

func TestNewGenerator(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name       string
		bufferSize int
	}{
		{"ZeroBuffer", 0},
		{"SmallBuffer", 1},
		{"MediumBuffer", 10},
		{"LargeBuffer", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewGenerator(tt.bufferSize)
			Expect(gen).ToNot(BeNil())
			Expect(gen.channel).ToNot(BeNil())
			Expect(gen.packets).ToNot(BeNil())
			Expect(len(gen.packets)).To(Equal(0))
			Expect(cap(gen.channel)).To(Equal(tt.bufferSize))
		})
	}
}

func TestRegisterSinglePacket(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(10)
	pkt := NewPacket(
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithDstAddr("192.168.1.1"),
	)

	gen.Register(pkt)
	packets := gen.Packets()
	Expect(len(packets)).To(Equal(1))
	Expect(packets[0]).To(Equal(pkt))
}

func TestRegisterMultiplePackets(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(10)
	pkt1 := NewPacket(WithProto(6), WithSrcAddr("10.0.0.1"))
	pkt2 := NewPacket(WithProto(17), WithSrcAddr("10.0.0.2"))
	pkt3 := NewPacket(WithProto(1), WithSrcAddr("10.0.0.3"))

	gen.Register(pkt1)
	gen.Register(pkt2)
	gen.Register(pkt3)

	packets := gen.Packets()
	Expect(len(packets)).To(Equal(3))
	Expect(packets[0]).To(Equal(pkt1))
	Expect(packets[1]).To(Equal(pkt2))
	Expect(packets[2]).To(Equal(pkt3))
}

func TestRegisterConcurrent(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(10)
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt := NewPacket(WithProto(6))
			gen.Register(pkt)
		}()
	}

	wg.Wait()
	packets := gen.Packets()
	Expect(len(packets)).To(Equal(numGoroutines))
}

func TestSendToChannel(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(10)
	pkt := NewPacket(
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithDstAddr("192.168.1.1"),
	)

	sent := gen.Send(pkt)
	Expect(sent).To(BeTrue())

	received := <-gen.Channel()
	Expect(received).To(Equal(pkt))
}

func TestSendMultiplePackets(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(10)
	packets := []*Packet{
		NewPacket(WithProto(6), WithSrcAddr("10.0.0.1")),
		NewPacket(WithProto(17), WithSrcAddr("10.0.0.2")),
		NewPacket(WithProto(1), WithSrcAddr("10.0.0.3")),
	}

	for _, pkt := range packets {
		sent := gen.Send(pkt)
		Expect(sent).To(BeTrue())
	}

	for i := 0; i < len(packets); i++ {
		received := <-gen.Channel()
		Expect(received).To(Equal(packets[i]))
	}
}

func TestSendToFullChannel(t *testing.T) {
	RegisterTestingT(t)

	// Create generator with buffer size 1
	gen := NewGenerator(1)
	pkt1 := NewPacket(WithProto(6))
	pkt2 := NewPacket(WithProto(17))

	// First send should succeed
	sent1 := gen.Send(pkt1)
	Expect(sent1).To(BeTrue())

	// Second send should fail (buffer full)
	sent2 := gen.Send(pkt2)
	Expect(sent2).To(BeFalse())

	// Receive packet to free space
	received := <-gen.Channel()
	Expect(received).To(Equal(pkt1))

	// Now send should succeed
	sent3 := gen.Send(pkt2)
	Expect(sent3).To(BeTrue())
}

func TestSendToZeroBufferChannel(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(0)
	pkt := NewPacket(WithProto(6))

	// Send to unbuffered channel without receiver should fail
	sent := gen.Send(pkt)
	Expect(sent).To(BeFalse())
}

func TestChannelReceive(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(5)
	pkt := NewPacket(
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)

	gen.Send(pkt)
	ch := gen.Channel()
	received := <-ch

	Expect(received.Protocol).To(Equal(pkt.Protocol))
	Expect(received.SrcAddr).To(Equal(pkt.SrcAddr))
	Expect(received.SrcPort).To(Equal(pkt.SrcPort))
	Expect(received.DstAddr).To(Equal(pkt.DstAddr))
	Expect(received.DstPort).To(Equal(pkt.DstPort))
}

func TestClose(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(10)
	pkt := NewPacket(WithProto(6))
	gen.Send(pkt)

	gen.Close()

	// Should be able to receive already sent packet
	received := <-gen.Channel()
	Expect(received).To(Equal(pkt))

	// Reading from closed channel should return nil
	received, ok := <-gen.Channel()
	Expect(ok).To(BeFalse())
	Expect(received).To(BeNil())
}

func TestPacketsReturnsACopy(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(10)
	pkt1 := NewPacket(WithProto(6))
	pkt2 := NewPacket(WithProto(17))

	gen.Register(pkt1)
	gen.Register(pkt2)

	packets1 := gen.Packets()
	packets2 := gen.Packets()

	// Should contain same packets
	Expect(packets1[0]).To(Equal(packets2[0]))
	Expect(packets1[1]).To(Equal(packets2[1]))

	// Modifying one slice should not affect the other
	packets1 = append(packets1, NewPacket(WithProto(1)))
	Expect(len(packets1)).To(Equal(3))
	Expect(len(packets2)).To(Equal(2))
	Expect(len(gen.Packets())).To(Equal(2))
}

func TestRegisterAndSendIntegration(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(10)
	
	// Register some packets
	pkt1 := NewPacket(
		WithProto(6),
		WithSrcAddr("10.0.0.1"),
		WithSrcPort(12345),
		WithDstAddr("192.168.1.1"),
		WithDstPort(80),
	)
	pkt2 := NewPacket(
		WithProto(17),
		WithSrcAddr("10.0.0.2"),
		WithSrcPort(54321),
		WithDstAddr("192.168.1.2"),
		WithDstPort(53),
	)

	gen.Register(pkt1)
	gen.Register(pkt2)

	// Verify registration
	packets := gen.Packets()
	Expect(len(packets)).To(Equal(2))

	// Send registered packets
	for _, pkt := range packets {
		sent := gen.Send(pkt)
		Expect(sent).To(BeTrue())
	}

	// Receive and verify
	received1 := <-gen.Channel()
	Expect(received1).To(Equal(pkt1))

	received2 := <-gen.Channel()
	Expect(received2).To(Equal(pkt2))
}

func TestConcurrentSendAndReceive(t *testing.T) {
	RegisterTestingT(t)

	gen := NewGenerator(100)
	numPackets := 50
	var wg sync.WaitGroup

	// Send packets concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numPackets; i++ {
			pkt := NewPacket(WithProto(6))
			gen.Send(pkt)
		}
	}()

	// Receive packets concurrently
	receivedCount := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numPackets; i++ {
			<-gen.Channel()
			receivedCount++
		}
	}()

	wg.Wait()
	Expect(receivedCount).To(Equal(numPackets))
}
