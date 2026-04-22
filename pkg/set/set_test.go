package set

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/fwsim/pkg/port"
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

func TestPortSetAddPortStruct(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	// port.Port with only a name — number must be resolved from the name.
	Expect(ps.Add(port.Port{Name: "http"})).To(Succeed())
	Expect(ps.Match(uint16(80))).To(BeTrue())
	Expect(ps.Match(uint16(443))).To(BeFalse())

	Expect(ps.Add(port.Port{Name: "https"})).To(Succeed())
	Expect(ps.Match(uint16(443))).To(BeTrue())

	// port.Port with both number and name — name takes precedence.
	ps2 := NewPortSet()
	Expect(ps2.Add(port.Port{Number: 0, Name: "ssh"})).To(Succeed())
	Expect(ps2.Match(uint16(22))).To(BeTrue())

	// port.Port with only a number.
	ps3 := NewPortSet()
	Expect(ps3.Add(port.Port{Number: 8080})).To(Succeed())
	Expect(ps3.Match(uint16(8080))).To(BeTrue())
}

func TestPortSetAdd(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	err := ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(uint16(80))).To(BeTrue())
	Expect(ps.Match(uint16(443))).To(BeFalse())
}

func TestPortSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	err := ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	err = ps.Add(uint16(443))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(uint16(80))).To(BeTrue())

	ps.Delete(uint16(80))
	Expect(ps.Match(uint16(80))).To(BeFalse())
	Expect(ps.Match(uint16(443))).To(BeTrue())
}

func TestPortSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()

	Expect(ps.Match(uint16(80))).To(BeFalse())

	err := ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(uint16(80))).To(BeTrue())
	Expect(ps.Match(uint16(8080))).To(BeFalse())
}

func TestPortSetStringOnePort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	err := ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.String()).To(Equal("80"))
}

func TestPortSetStringMultiplePorts(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	err := ps.Add(uint16(443))
	Expect(err).NotTo(HaveOccurred())
	err = ps.Add(uint16(80))
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.String()).To(Equal("{80,443}"))
}

func TestPortSetAddRange(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add(port.Port{Number: 1024, End: 65535})).To(Succeed())
	Expect(ps.Match(uint16(1024))).To(BeTrue())
	Expect(ps.Match(uint16(8080))).To(BeTrue())
	Expect(ps.Match(uint16(65535))).To(BeTrue())
	Expect(ps.Match(uint16(1023))).To(BeFalse())
	Expect(ps.Match(uint16(80))).To(BeFalse())
}

func TestPortSetAddRangeString(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add("1024-65535")).To(Succeed())
	Expect(ps.Match(uint16(1024))).To(BeTrue())
	Expect(ps.Match(uint16(8080))).To(BeTrue())
	Expect(ps.Match(uint16(65535))).To(BeTrue())
	Expect(ps.Match(uint16(1023))).To(BeFalse())
}

func TestPortSetAddRangeAndSinglePort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add(uint16(80))).To(Succeed())
	Expect(ps.Add("1024-65535")).To(Succeed())
	Expect(ps.Match(uint16(80))).To(BeTrue())
	Expect(ps.Match(uint16(8080))).To(BeTrue())
	Expect(ps.Match(uint16(443))).To(BeFalse())
}

func TestPortSetStringWithRange(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add("1024-65535")).To(Succeed())
	Expect(ps.String()).To(Equal("1024-65535"))
}

func TestPortSetStringWithRangeAndPort(t *testing.T) {
	RegisterTestingT(t)

	ps := NewPortSet()
	Expect(ps.Add(uint16(80))).To(Succeed())
	Expect(ps.Add("1024-65535")).To(Succeed())
	Expect(ps.String()).To(Equal("{80,1024-65535}"))
}

func TestProtoSetAdd(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	err := ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(proto.TCP)).To(BeTrue())
	Expect(ps.Match(proto.UDP)).To(BeFalse())
}

func TestProtoSetDelete(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	err := ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	err = ps.Add(proto.UDP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(proto.TCP)).To(BeTrue())

	ps.Delete(proto.TCP)
	Expect(ps.Match(proto.TCP)).To(BeFalse())
	Expect(ps.Match(proto.UDP)).To(BeTrue())
}

func TestProtoSetMatch(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()

	Expect(ps.Match(proto.TCP)).To(BeFalse())

	err := ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.Match(proto.TCP)).To(BeTrue())
	Expect(ps.Match(proto.UDP)).To(BeFalse())
}

func TestProtoSetStringOneProto(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	err := ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.String()).To(Equal("tcp"))
}

func TestProtoSetStringMultipleProtos(t *testing.T) {
	RegisterTestingT(t)

	ps := NewProtoSet()
	err := ps.Add(proto.UDP)
	Expect(err).NotTo(HaveOccurred())
	err = ps.Add(proto.TCP)
	Expect(err).NotTo(HaveOccurred())
	Expect(ps.String()).To(Equal("{tcp,udp}"))
}

func TestIPSetAdd(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(ipnet)
	Expect(err).NotTo(HaveOccurred())
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
	err = s.Add(net1)
	Expect(err).NotTo(HaveOccurred())
	err = s.Add(net2)
	Expect(err).NotTo(HaveOccurred())
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
	err = s.Add(ipnet)
	Expect(err).NotTo(HaveOccurred())
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
	err = s.Add(net1)
	Expect(err).NotTo(HaveOccurred())
	err = s.Add(net2)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.Match(net.ParseIP("10.1.2.3"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("192.168.1.1"))).To(BeTrue())
	Expect(s.Match(net.ParseIP("172.16.0.1"))).To(BeFalse())
}

func TestIPSetStringOneNet(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(ipnet)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.String()).To(Equal("10.0.0.0/8"))
}

func TestIPSetStringMultipleNets(t *testing.T) {
	RegisterTestingT(t)

	s := NewIPSet()
	_, net1, err := net.ParseCIDR("192.168.0.0/16")
	Expect(err).ToNot(HaveOccurred())
	_, net2, err := net.ParseCIDR("10.0.0.0/8")
	Expect(err).ToNot(HaveOccurred())
	err = s.Add(net1)
	Expect(err).NotTo(HaveOccurred())
	err = s.Add(net2)
	Expect(err).NotTo(HaveOccurred())
	Expect(s.String()).To(Equal("{10.0.0.0/8,192.168.0.0/16}"))
}

func TestSetTypes(t *testing.T) {
	RegisterTestingT(t)

	Expect(NewIPSet().Type()).To(Equal(TypeIP))
	Expect(NewPortSet().Type()).To(Equal(TypePort))
	Expect(NewProtoSet().Type()).To(Equal(TypeProto))
	Expect(NewIPPortSet().Type()).To(Equal(TypeIPPort))
}
