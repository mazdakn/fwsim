package set

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"
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

	ps.Add(80)
	Expect(ps.Match(80)).To(BeTrue())
	Expect(ps.Match(443)).To(BeFalse())
}

func TestPortSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	ps.Add(80)
	ps.Add(443)
	Expect(ps.Match(80)).To(BeTrue())

	ps.Delete(80)
	Expect(ps.Match(80)).To(BeFalse())
	Expect(ps.Match(443)).To(BeTrue())
}

func TestPortSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	Expect(ps.Match(80)).To(BeFalse())

	ps.Add(80)
	Expect(ps.Match(80)).To(BeTrue())
	Expect(ps.Match(8080)).To(BeFalse())
}

func TestPortSetStringOnePort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	ps.Add(80)
	Expect(ps.String()).To(Equal("80"))
}

func TestPortSetStringMultiplePorts(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	ps.Add(443)
	ps.Add(80)
	Expect(ps.String()).To(Equal("{80,443}"))
}

func TestProtoSetAdd(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	ps.Add(6)
	Expect(ps.Match(6)).To(BeTrue())
	Expect(ps.Match(17)).To(BeFalse())
}

func TestProtoSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	ps.Add(6)
	ps.Add(17)
	Expect(ps.Match(6)).To(BeTrue())

	ps.Delete(6)
	Expect(ps.Match(6)).To(BeFalse())
	Expect(ps.Match(17)).To(BeTrue())
}

func TestProtoSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	Expect(ps.Match(6)).To(BeFalse())

	ps.Add(6)
	Expect(ps.Match(6)).To(BeTrue())
	Expect(ps.Match(17)).To(BeFalse())
}

func TestProtoSetStringOneProto(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	ps.Add(6)
	Expect(ps.String()).To(Equal("6"))
}

func TestProtoSetStringMultipleProtos(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	ps.Add(17)
	ps.Add(6)
	Expect(ps.String()).To(Equal("{6,17}"))
}

func TestIPSetAdd(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.Add(ipnet)
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("192.168.0.1"))).To(BeFalse())
}

func TestIPSetDelete(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	s.Add(net1)
	s.Add(net2)
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())

	s.Delete(net1)
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeFalse())
	Expect(s.Match(net.ParseIP("192.168.1.1"))).To(BeTrue())
}

func TestIPSetMatch(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	Expect(s.Match(net.ParseIP("10.0.0.1"))).To(BeFalse())

	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.Add(ipnet)
	Expect(s.Match(net.ParseIP("10.0.0.1"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("172.16.0.1"))).To(BeFalse())
}

func TestIPSetMatchMultipleNets(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	s.Add(net1)
	s.Add(net2)
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("192.168.1.1"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("172.16.0.1"))).To(BeFalse())
}

func TestIPSetStringOneNet(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.Add(ipnet)
	Expect(s.String()).To(Equal("10.0.0.0/8"))
}

func TestIPSetStringMultipleNets(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.Add(net1)
	s.Add(net2)
	Expect(s.String()).To(Equal("{10.0.0.0/8,192.168.0.0/16}"))
}

func TestPortSetNegatedMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	ps.Negated = true
	ps.Add(80)

	// Negated set matches ports NOT in the set
	Expect(ps.Match(80)).To(BeFalse())
	Expect(ps.Match(443)).To(BeTrue())
	Expect(ps.Match(8080)).To(BeTrue())
}

func TestPortSetNegatedString(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	ps.Negated = true
	ps.Add(80)
	Expect(ps.String()).To(Equal("!80"))

	ps2 := NewPortSet()
	ps2.Negated = true
	ps2.Add(80)
	ps2.Add(443)
	Expect(ps2.String()).To(Equal("!{80,443}"))
}

func TestProtoSetNegatedMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	ps.Negated = true
	ps.Add(6)

	// Negated set matches protocols NOT in the set
	Expect(ps.Match(6)).To(BeFalse())
	Expect(ps.Match(17)).To(BeTrue())
	Expect(ps.Match(1)).To(BeTrue())
}

func TestProtoSetNegatedString(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	ps.Negated = true
	ps.Add(6)
	Expect(ps.String()).To(Equal("!6"))

	ps2 := NewProtoSet()
	ps2.Negated = true
	ps2.Add(6)
	ps2.Add(17)
	Expect(ps2.String()).To(Equal("!{6,17}"))
}

func TestIPSetNegatedMatch(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	s.Negated = true
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.Add(ipnet)

	// Negated set matches IPs NOT in the network
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeFalse())
	Expect(s.Match(net.ParseIP("192.168.0.1"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("172.16.0.1"))).To(BeTrue())
}

func TestIPSetNegatedString(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	s.Negated = true
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	s.Add(ipnet)
	Expect(s.String()).To(Equal("!10.0.0.0/8"))

	s2 := NewIPSet()
	s2.Negated = true
	_, net1, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	s2.Add(net1)
	s2.Add(net2)
	Expect(s2.String()).To(Equal("!{10.0.0.0/8,192.168.0.0/16}"))
}

