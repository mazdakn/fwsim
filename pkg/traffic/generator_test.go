package traffic

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestNewGeneratorEmpty(t *testing.T) {
	RegisterTestingT(t)

	g := NewGenerator("test-generator")
	Expect(g).ToNot(BeNil())
	Expect(g.name).To(Equal("test-generator"))
	Expect(g.rate).To(Equal(time.Second * 1))
	Expect(g.packets).To(BeNil())
	Expect(g.egress).To(BeNil())
	Expect(g.logCtx).ToNot(BeNil())
}

func TestWithRate(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name string
		rate time.Duration
	}{
		{"HalfSecond", time.Millisecond * 500},
		{"OneSecond", time.Second},
		{"TwoSeconds", time.Second * 2},
		{"TenSeconds", time.Second * 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGenerator("test-generator", WithRate(tt.rate))
			Expect(g.rate).To(Equal(tt.rate))
		})
	}
}

func TestWithEgress(t *testing.T) {
	RegisterTestingT(t)

	egress := make(chan []Packet, 1)
	g := NewGenerator("test-generator", WithEgress(egress))
	Expect(g.egress).ToNot(BeNil())
}

func TestNewGeneratorMultipleOptions(t *testing.T) {
	RegisterTestingT(t)

	egress := make(chan []Packet, 1)
	rate := time.Millisecond * 100

	g := NewGenerator("test-generator", WithRate(rate), WithEgress(egress))

	Expect(g.name).To(Equal("test-generator"))
	Expect(g.rate).To(Equal(rate))
	Expect(g.egress).ToNot(BeNil())
}

func TestGeneratorRegister(t *testing.T) {
	RegisterTestingT(t)

	t.Run("register single packet", func(t *testing.T) {
		g := NewGenerator("test-generator")
		pkt := NewPacket(WithProto(6), WithSrcAddr("10.0.0.1"), WithDstAddr("192.168.1.1"))
		g.RegisterPackets(pkt)
		Expect(g.packets).To(HaveLen(1))
		Expect(g.packets[0].Protocol).To(Equal(uint8(6)))
	})

	t.Run("register multiple packets", func(t *testing.T) {
		g := NewGenerator("test-generator")
		pkt1 := NewPacket(WithProto(6), WithSrcAddr("10.0.0.1"), WithDstAddr("192.168.1.1"))
		pkt2 := NewPacket(WithProto(17), WithSrcAddr("10.0.0.2"), WithDstAddr("192.168.1.2"))
		pkt3 := NewPacket(WithProto(1), WithSrcAddr("10.0.0.3"), WithDstAddr("192.168.1.3"))
		g.RegisterPackets(pkt1, pkt2, pkt3)
		Expect(g.packets).To(HaveLen(3))
		Expect(g.packets[0].Protocol).To(Equal(uint8(6)))
		Expect(g.packets[1].Protocol).To(Equal(uint8(17)))
		Expect(g.packets[2].Protocol).To(Equal(uint8(1)))
	})
}

func TestGeneratorFlush(t *testing.T) {
	RegisterTestingT(t)

	t.Run("flush empty generator", func(t *testing.T) {
		g := NewGenerator("test-generator")
		g.Flush()
		Expect(g.packets).To(BeNil())
	})

	t.Run("flush generator with packets", func(t *testing.T) {
		g := NewGenerator("test-generator")
		pkt1 := NewPacket(WithProto(6))
		pkt2 := NewPacket(WithProto(17))
		g.RegisterPackets(pkt1, pkt2)
		Expect(g.packets).To(HaveLen(2))
		g.Flush()
		Expect(g.packets).To(BeNil())
	})

	t.Run("register after flush", func(t *testing.T) {
		g := NewGenerator("test-generator")
		pkt1 := NewPacket(WithProto(6))
		g.RegisterPackets(pkt1)
		g.Flush()
		pkt2 := NewPacket(WithProto(17))
		g.RegisterPackets(pkt2)
		Expect(g.packets).To(HaveLen(1))
		Expect(g.packets[0].Protocol).To(Equal(uint8(17)))
	})
}

func TestGeneratorSend(t *testing.T) {
	RegisterTestingT(t)

	t.Run("send empty packets", func(t *testing.T) {
		egress := make(chan []Packet, 1)
		g := NewGenerator("test-generator", WithEgress(egress))
		g.Send()
		received := <-egress
		Expect(received).To(BeNil())
	})

	t.Run("send registered packets", func(t *testing.T) {
		egress := make(chan []Packet, 1)
		g := NewGenerator("test-generator", WithEgress(egress))
		pkt1 := NewPacket(WithProto(6), WithSrcAddr("10.0.0.1"), WithDstAddr("192.168.1.1"))
		pkt2 := NewPacket(WithProto(17), WithSrcAddr("10.0.0.2"), WithDstAddr("192.168.1.2"))
		g.RegisterPackets(pkt1, pkt2)
		g.Send()
		received := <-egress
		Expect(received).To(HaveLen(2))
		Expect(received[0].Protocol).To(Equal(uint8(6)))
		Expect(received[1].Protocol).To(Equal(uint8(17)))
	})
}

func TestGeneratorStart(t *testing.T) {
	RegisterTestingT(t)

	t.Run("start and cancel context", func(t *testing.T) {
		egress := make(chan []Packet, 10)
		rate := time.Millisecond * 50
		g := NewGenerator("test-generator", WithRate(rate), WithEgress(egress))
		pkt := NewPacket(WithProto(6))
		g.RegisterPackets(pkt)

		ctx, cancel := context.WithCancel(context.Background())
		g.Start(ctx)

		// Use Eventually to wait for at least one packet to be sent
		Eventually(func() int {
			return len(egress)
		}, time.Second, time.Millisecond*10).Should(BeNumerically(">=", 1))

		cancel()
	})

	t.Run("start with context timeout", func(t *testing.T) {
		egress := make(chan []Packet, 10)
		rate := time.Millisecond * 50
		g := NewGenerator("test-generator", WithRate(rate), WithEgress(egress))
		pkt := NewPacket(WithProto(6))
		g.RegisterPackets(pkt)

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
		defer cancel()
		g.Start(ctx)

		// Use Eventually to wait for at least one packet to be sent
		Eventually(func() int {
			return len(egress)
		}, time.Second, time.Millisecond*10).Should(BeNumerically(">=", 1))
	})
}
