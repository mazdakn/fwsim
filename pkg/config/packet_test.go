package config

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/firecore/port"
	"github.com/mazdakn/firecore/proto"
)

const testPacketsYAML = `
metadata:
  name: access backend
src_addr: 192.168.1.5
dst_addr: 1.1.1.1
proto: 7
src_port: 30000
dst_port: 80
`

func TestPacketsFromBytes(t *testing.T) {
	RegisterTestingT(t)

	pkts, err := PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())
	Expect(pkts).To(HaveLen(1))

	Expect(pkts[0].SrcAddr.String()).To(Equal("192.168.1.5"))
	Expect(pkts[0].DstAddr.String()).To(Equal("1.1.1.1"))
	Expect(pkts[0].Proto).To(Equal(proto.Proto(7)))
	Expect(pkts[0].SrcPort).To(Equal(uint16(30000)))
	Expect(pkts[0].DstPort).To(Equal(uint16(80)))
}

func TestPacketsFromBytesInvalid(t *testing.T) {
	RegisterTestingT(t)

	pkts, err := PacketsFromBytes([]byte("not: valid: yaml: ["))
	Expect(err).ToNot(BeNil())
	Expect(pkts).To(BeNil())
}

const testPacketsNamedPortYAML = `
metadata:
  name: http request
src_addr: 192.168.1.10
dst_addr: 1.1.1.1
proto: 6
src_port: ssh
dst_port: http
`

func TestPacketsFromBytesWithNamedPorts(t *testing.T) {
	RegisterTestingT(t)

	pkts, err := PacketsFromBytes([]byte(testPacketsNamedPortYAML))
	Expect(err).To(BeNil())
	Expect(pkts).To(HaveLen(1))

	// src_port "ssh" → 22, dst_port "http" → 80
	Expect(pkts[0].SrcPort).To(Equal(uint16(22)))
	Expect(pkts[0].DstPort).To(Equal(uint16(80)))
}

func TestToPacketWithNameOnlyPort(t *testing.T) {
	RegisterTestingT(t)

	p := &Packet{
		SrcAddr: "192.168.1.5",
		DstAddr: "1.1.1.1",
		Proto:   proto.TCP,
		SrcPort: port.Port{Name: "ssh"},
		DstPort: port.Port{Name: "https"},
	}
	pkt := p.ToPacket()
	Expect(pkt.SrcPort).To(Equal(uint16(22)))
	Expect(pkt.DstPort).To(Equal(uint16(443)))
}
