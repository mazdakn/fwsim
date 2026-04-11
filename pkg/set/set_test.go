package set

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/fwsim/pkg/proto"
)

func TestSetAdd(t *testing.T) {
	RegisterTestingT(t)

	s := New[string]()

	s.Add("foo")
	Expect(s.Exists("foo")).To(BeTrue())
	Expect(s.Exists("bar")).To(BeFalse())
}

func TestSetDelete(t *testing.T) {
	RegisterTestingT(t)

	s := New[int]()

	s.Add(1)
	s.Add(2)
	Expect(s.Exists(1)).To(BeTrue())

	s.Delete(1)
	Expect(s.Exists(1)).To(BeFalse())
	Expect(s.Exists(2)).To(BeTrue())
}

func TestSetExists(t *testing.T) {
	RegisterTestingT(t)

	s := New[string]()

	Expect(s.Exists("missing")).To(BeFalse())

	s.Add("present")
	Expect(s.Exists("present")).To(BeTrue())
	Expect(s.Exists("missing")).To(BeFalse())
}

func TestPortSetAdd(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	ps.AddPort(80)
	Expect(ps.MatchPort(80)).To(BeTrue())
	Expect(ps.MatchPort(443)).To(BeFalse())
}

func TestPortSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	ps.AddPort(80)
	ps.AddPort(443)
	Expect(ps.MatchPort(80)).To(BeTrue())

	ps.Delete(80)
	Expect(ps.MatchPort(80)).To(BeFalse())
	Expect(ps.MatchPort(443)).To(BeTrue())
}

func TestPortSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	Expect(ps.MatchPort(80)).To(BeFalse())

	ps.AddPort(80)
	Expect(ps.MatchPort(80)).To(BeTrue())
	Expect(ps.MatchPort(8080)).To(BeFalse())
}

func TestPortSetStringOnePort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	ps.AddPort(80)
	Expect(ps.String()).To(Equal("80"))
}

func TestPortSetStringMultiplePorts(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	ps.AddPort(443)
	ps.AddPort(80)
	Expect(ps.String()).To(Equal("{80,443}"))
}

func TestProtoSetAdd(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	ps.AddProto(proto.TCP)
	Expect(ps.MatchProto(proto.TCP)).To(BeTrue())
	Expect(ps.MatchProto(proto.UDP)).To(BeFalse())
}

func TestProtoSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	ps.AddProto(proto.TCP)
	ps.AddProto(proto.UDP)
	Expect(ps.MatchProto(proto.TCP)).To(BeTrue())

	ps.Delete(proto.TCP)
	Expect(ps.MatchProto(proto.TCP)).To(BeFalse())
	Expect(ps.MatchProto(proto.UDP)).To(BeTrue())
}

func TestProtoSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	Expect(ps.MatchProto(proto.TCP)).To(BeFalse())

	ps.AddProto(proto.TCP)
	Expect(ps.MatchProto(proto.TCP)).To(BeTrue())
	Expect(ps.MatchProto(proto.UDP)).To(BeFalse())
}

func TestProtoSetStringOneProto(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	ps.AddProto(proto.TCP)
	Expect(ps.String()).To(Equal("tcp"))
}

func TestProtoSetStringMultipleProtos(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	ps.AddProto(proto.UDP)
	ps.AddProto(proto.TCP)
	Expect(ps.String()).To(Equal("{tcp,udp}"))
}

func TestIPSetAdd(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.AddNet(ipnet)
	Expect(s.MatchIP(net.ParseIP("10.1.2.3"))).To(BeTrue())
	Expect(s.MatchIP(net.ParseIP("192.168.0.1"))).To(BeFalse())
}

func TestIPSetDelete(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	s.AddNet(net1)
	s.AddNet(net2)
	Expect(s.MatchIP(net.ParseIP("10.1.2.3"))).To(BeTrue())

	s.DeleteNet(net1)
	Expect(s.MatchIP(net.ParseIP("10.1.2.3"))).To(BeFalse())
	Expect(s.MatchIP(net.ParseIP("192.168.1.1"))).To(BeTrue())
}

func TestIPSetMatch(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	Expect(s.MatchIP(net.ParseIP("10.0.0.1"))).To(BeFalse())

	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.AddNet(ipnet)
	Expect(s.MatchIP(net.ParseIP("10.0.0.1"))).To(BeTrue())
	Expect(s.MatchIP(net.ParseIP("172.16.0.1"))).To(BeFalse())
}

func TestIPSetMatchMultipleNets(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	s.AddNet(net1)
	s.AddNet(net2)
	Expect(s.MatchIP(net.ParseIP("10.1.2.3"))).To(BeTrue())
	Expect(s.MatchIP(net.ParseIP("192.168.1.1"))).To(BeTrue())
	Expect(s.MatchIP(net.ParseIP("172.16.0.1"))).To(BeFalse())
}

func TestIPSetStringOneNet(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.AddNet(ipnet)
	Expect(s.String()).To(Equal("10.0.0.0/8"))
}

func TestIPSetStringMultipleNets(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.AddNet(net1)
	s.AddNet(net2)
	Expect(s.String()).To(Equal("{10.0.0.0/8,192.168.0.0/16}"))
}
