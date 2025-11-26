package traffic

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestNewGenerator(t *testing.T) {
	RegisterTestingT(t)

	t.Run("empty generator with name", func(t *testing.T) {
		gen := NewGenerator("test-gen")
		Expect(gen).ToNot(BeNil())
		Expect(gen.name).To(Equal("test-gen"))
		Expect(gen.rate).To(Equal(time.Second * 1))
		Expect(gen.packets).To(BeEmpty())
		Expect(gen.egress).To(BeNil())
	})

	t.Run("generator with rate option", func(t *testing.T) {
		gen := NewGenerator("test-gen", WithRate(time.Second*5))
		Expect(gen.name).To(Equal("test-gen"))
		Expect(gen.rate).To(Equal(time.Second * 5))
	})

	t.Run("generator with egress channel", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen", WithEgress(egress))
		Expect(gen.name).To(Equal("test-gen"))
		Expect(gen.egress).ToNot(BeNil())
	})

	t.Run("generator with multiple options", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen",
			WithRate(time.Millisecond*100),
			WithEgress(egress))
		Expect(gen.name).To(Equal("test-gen"))
		Expect(gen.rate).To(Equal(time.Millisecond * 100))
		Expect(gen.egress).ToNot(BeNil())
	})
}

func TestGeneratorRegister(t *testing.T) {
	RegisterTestingT(t)

	t.Run("register single packet", func(t *testing.T) {
		gen := NewGenerator("test-gen")
		pkt := NewPacket(
			WithProto(6),
			WithSrcAddr("10.0.0.1"),
			WithDstAddr("192.168.1.1"),
			WithSrcPort(12345),
			WithDstPort(80),
		)
		gen.Register(pkt)
		Expect(gen.packets).To(HaveLen(1))
		Expect(gen.packets[0]).To(Equal(pkt))
	})

	t.Run("register multiple packets", func(t *testing.T) {
		gen := NewGenerator("test-gen")
		pkt1 := NewPacket(WithProto(6), WithSrcAddr("10.0.0.1"), WithDstAddr("192.168.1.1"))
		pkt2 := NewPacket(WithProto(17), WithSrcAddr("10.0.0.2"), WithDstAddr("192.168.1.2"))
		pkt3 := NewPacket(WithProto(1), WithSrcAddr("10.0.0.3"), WithDstAddr("192.168.1.3"))

		gen.Register(pkt1)
		gen.Register(pkt2)
		gen.Register(pkt3)

		Expect(gen.packets).To(HaveLen(3))
		Expect(gen.packets[0]).To(Equal(pkt1))
		Expect(gen.packets[1]).To(Equal(pkt2))
		Expect(gen.packets[2]).To(Equal(pkt3))
	})

	t.Run("register packets with IPv6", func(t *testing.T) {
		gen := NewGenerator("test-gen")
		pkt := NewPacket(
			WithProto(6),
			WithSrcAddr("2001:db8::1"),
			WithDstAddr("cafe::1"),
			WithSrcPort(54321),
			WithDstPort(443),
		)
		gen.Register(pkt)
		Expect(gen.packets).To(HaveLen(1))
		Expect(gen.packets[0].SrcAddr.String()).To(Equal("2001:db8::1"))
	})
}

func TestGeneratorFlush(t *testing.T) {
	RegisterTestingT(t)

	t.Run("flush empty generator", func(t *testing.T) {
		gen := NewGenerator("test-gen")
		gen.Flush()
		Expect(gen.packets).To(BeNil())
	})

	t.Run("flush generator with packets", func(t *testing.T) {
		gen := NewGenerator("test-gen")
		pkt1 := NewPacket(WithProto(6))
		pkt2 := NewPacket(WithProto(17))
		gen.Register(pkt1)
		gen.Register(pkt2)
		Expect(gen.packets).To(HaveLen(2))

		gen.Flush()
		Expect(gen.packets).To(BeNil())
	})

	t.Run("register after flush", func(t *testing.T) {
		gen := NewGenerator("test-gen")
		pkt1 := NewPacket(WithProto(6))
		gen.Register(pkt1)
		gen.Flush()

		pkt2 := NewPacket(WithProto(17))
		gen.Register(pkt2)
		Expect(gen.packets).To(HaveLen(1))
		Expect(gen.packets[0]).To(Equal(pkt2))
	})
}

func TestGeneratorSend(t *testing.T) {
	RegisterTestingT(t)

	t.Run("send single packet", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen", WithEgress(egress))
		pkt := NewPacket(
			WithProto(6),
			WithSrcAddr("10.0.0.1"),
			WithDstAddr("192.168.1.1"),
			WithSrcPort(12345),
			WithDstPort(80),
		)
		gen.Register(pkt)
		gen.Send()

		Expect(egress).To(HaveLen(1))
		receivedPkt := <-egress
		Expect(receivedPkt.Protocol).To(Equal(uint8(6)))
		Expect(receivedPkt.SrcAddr.String()).To(Equal("10.0.0.1"))
		Expect(receivedPkt.DstAddr.String()).To(Equal("192.168.1.1"))
		Expect(receivedPkt.SrcPort).To(Equal(uint16(12345)))
		Expect(receivedPkt.DstPort).To(Equal(uint16(80)))
	})

	t.Run("send multiple packets", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen", WithEgress(egress))

		pkt1 := NewPacket(WithProto(6), WithSrcAddr("10.0.0.1"), WithDstAddr("192.168.1.1"))
		pkt2 := NewPacket(WithProto(17), WithSrcAddr("10.0.0.2"), WithDstAddr("192.168.1.2"))
		pkt3 := NewPacket(WithProto(1), WithSrcAddr("10.0.0.3"), WithDstAddr("192.168.1.3"))

		gen.Register(pkt1)
		gen.Register(pkt2)
		gen.Register(pkt3)
		gen.Send()

		Expect(egress).To(HaveLen(3))

		receivedPkt1 := <-egress
		Expect(receivedPkt1.Protocol).To(Equal(uint8(6)))
		Expect(receivedPkt1.SrcAddr.String()).To(Equal("10.0.0.1"))

		receivedPkt2 := <-egress
		Expect(receivedPkt2.Protocol).To(Equal(uint8(17)))
		Expect(receivedPkt2.SrcAddr.String()).To(Equal("10.0.0.2"))

		receivedPkt3 := <-egress
		Expect(receivedPkt3.Protocol).To(Equal(uint8(1)))
		Expect(receivedPkt3.SrcAddr.String()).To(Equal("10.0.0.3"))
	})

	t.Run("send with no packets registered", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen", WithEgress(egress))
		gen.Send()
		Expect(egress).To(HaveLen(0))
	})

	t.Run("send multiple times", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen", WithEgress(egress))
		pkt := NewPacket(WithProto(6))
		gen.Register(pkt)

		gen.Send()
		Expect(egress).To(HaveLen(1))

		gen.Send()
		Expect(egress).To(HaveLen(2))
	})

	t.Run("send after flush", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen", WithEgress(egress))
		pkt := NewPacket(WithProto(6))
		gen.Register(pkt)
		gen.Flush()
		gen.Send()
		Expect(egress).To(HaveLen(0))
	})
}

func TestGeneratorStart(t *testing.T) {
	RegisterTestingT(t)

	t.Run("start sends packets periodically", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen",
			WithRate(time.Millisecond*50),
			WithEgress(egress))

		pkt := NewPacket(WithProto(6), WithSrcAddr("10.0.0.1"))
		gen.Register(pkt)

		ctx, cancel := context.WithCancel(context.Background())
		gen.Start(ctx)

		// Wait for a few packets to be sent
		time.Sleep(time.Millisecond * 160)
		cancel()

		// Give goroutine time to exit
		time.Sleep(time.Millisecond * 10)

		// Should have received at least 2-3 packets
		count := len(egress)
		Expect(count).To(BeNumerically(">=", 2))
		Expect(count).To(BeNumerically("<=", 4))
	})

	t.Run("start stops on context cancellation", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen",
			WithRate(time.Millisecond*50),
			WithEgress(egress))

		pkt := NewPacket(WithProto(6))
		gen.Register(pkt)

		ctx, cancel := context.WithCancel(context.Background())
		gen.Start(ctx)

		// Wait for a couple packets
		time.Sleep(time.Millisecond * 110)
		initialCount := len(egress)

		// Cancel context
		cancel()
		time.Sleep(time.Millisecond * 200)

		// No more packets should be sent after cancellation
		finalCount := len(egress)
		Expect(finalCount).To(Equal(initialCount))
	})

	t.Run("start with no packets registered", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen",
			WithRate(time.Millisecond*50),
			WithEgress(egress))

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*110)
		defer cancel()

		gen.Start(ctx)
		time.Sleep(time.Millisecond * 120)

		Expect(egress).To(HaveLen(0))
	})

	t.Run("start with context timeout", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen",
			WithRate(time.Millisecond*50),
			WithEgress(egress))

		pkt := NewPacket(WithProto(17))
		gen.Register(pkt)

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*110)
		defer cancel()

		gen.Start(ctx)
		time.Sleep(time.Millisecond * 160)

		// Should have received packets before timeout
		count := len(egress)
		Expect(count).To(BeNumerically(">=", 1))
		Expect(count).To(BeNumerically("<=", 3))
	})

	t.Run("start with multiple packets", func(t *testing.T) {
		egress := make(chan Packet, 30)
		gen := NewGenerator("test-gen",
			WithRate(time.Millisecond*50),
			WithEgress(egress))

		pkt1 := NewPacket(WithProto(6), WithSrcAddr("10.0.0.1"))
		pkt2 := NewPacket(WithProto(17), WithSrcAddr("10.0.0.2"))
		gen.Register(pkt1)
		gen.Register(pkt2)

		ctx, cancel := context.WithCancel(context.Background())
		gen.Start(ctx)

		time.Sleep(time.Millisecond * 160)
		cancel()
		time.Sleep(time.Millisecond * 10)

		// Each tick should send both packets
		count := len(egress)
		Expect(count).To(BeNumerically(">=", 4)) // At least 2 ticks * 2 packets
		Expect(count % 2).To(Equal(0))           // Should be even number
	})
}

func TestGeneratorOptions(t *testing.T) {
	RegisterTestingT(t)

	t.Run("WithEgress option", func(t *testing.T) {
		egress := make(chan Packet, 10)
		gen := NewGenerator("test-gen", WithEgress(egress))
		Expect(gen.egress).ToNot(BeNil())
	})

	t.Run("WithRate option", func(t *testing.T) {
		tests := []struct {
			name string
			rate time.Duration
		}{
			{"1 second", time.Second},
			{"100 milliseconds", time.Millisecond * 100},
			{"5 seconds", time.Second * 5},
			{"1 minute", time.Minute},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				gen := NewGenerator("test-gen", WithRate(tt.rate))
				Expect(gen.rate).To(Equal(tt.rate))
			})
		}
	})

	t.Run("options can be applied in any order", func(t *testing.T) {
		egress := make(chan Packet, 10)
		rate := time.Millisecond * 200

		gen1 := NewGenerator("test-gen",
			WithRate(rate),
			WithEgress(egress))

		gen2 := NewGenerator("test-gen",
			WithEgress(egress),
			WithRate(rate))

		Expect(gen1.rate).To(Equal(gen2.rate))
		Expect(gen1.egress).To(Equal(gen2.egress))
	})
}
