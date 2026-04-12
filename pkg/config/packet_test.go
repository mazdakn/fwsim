package config

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
)

const testPacketsYAML = `
packets:
  - name: access backend
    src_addr: 192.168.1.5
    dst_addr: 1.1.1.1
    proto: 7
    src_port: 30000
    dst_port: 80
  - name: access app1
    src_addr: 10.0.0.1
    dst_addr: 2.2.2.2
    proto: 7
    src_port: 12345
    dst_port: 8080
  - name: dns traffic
    src_addr: 172.16.0.1
    dst_addr: 8.8.8.8
    proto: 17
    src_port: 54321
    dst_port: 53
  - name: access backend
    src_addr: 192.168.1.5
    dst_addr: 1.1.1.1
    proto: 7
    src_port: 30000
    dst_port: 80
  - name: dns traffic
    src_addr: 172.16.0.1
    dst_addr: 8.8.8.8
    proto: 17
    src_port: 54321
    dst_port: 53
`

func TestPacketsFromBytes(t *testing.T) {
	RegisterTestingT(t)

	pkts, err := PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())
	Expect(len(pkts)).To(Equal(5))

	// Verify first packet
	Expect(pkts[0].SrcAddr.String()).To(Equal("192.168.1.5"))
	Expect(pkts[0].DstAddr.String()).To(Equal("1.1.1.1"))
	Expect(pkts[0].Proto).To(Equal(proto.Proto(7)))
	Expect(pkts[0].SrcPort).To(Equal(uint16(30000)))
	Expect(pkts[0].DstPort).To(Equal(uint16(80)))

	// Verify second packet
	Expect(pkts[1].SrcAddr.String()).To(Equal("10.0.0.1"))
	Expect(pkts[1].DstAddr.String()).To(Equal("2.2.2.2"))
	Expect(pkts[1].Proto).To(Equal(proto.Proto(7)))
	Expect(pkts[1].SrcPort).To(Equal(uint16(12345)))
	Expect(pkts[1].DstPort).To(Equal(uint16(8080)))
}

func TestPacketsFromBytesInvalid(t *testing.T) {
	RegisterTestingT(t)

	pkts, err := PacketsFromBytes([]byte("not: valid: yaml: ["))
	Expect(err).ToNot(BeNil())
	Expect(pkts).To(BeNil())
}

const testPacketsNamedPortYAML = `
packets:
  - name: http request
    src_addr: 192.168.1.10
    dst_addr: 1.1.1.1
    proto: 6
    src_port: ssh
    dst_port: http
  - name: https request
    src_addr: 10.0.0.5
    dst_addr: 2.2.2.2
    proto: 6
    src_port: 12345
    dst_port: https
`

func TestPacketsFromBytesWithNamedPorts(t *testing.T) {
	RegisterTestingT(t)

	pkts, err := PacketsFromBytes([]byte(testPacketsNamedPortYAML))
	Expect(err).To(BeNil())
	Expect(pkts).To(HaveLen(2))

	// First packet: src_port "ssh" → 22, dst_port "http" → 80
	Expect(pkts[0].SrcPort).To(Equal(uint16(22)))
	Expect(pkts[0].DstPort).To(Equal(uint16(80)))

	// Second packet: src_port numeric 12345, dst_port "https" → 443
	Expect(pkts[1].SrcPort).To(Equal(uint16(12345)))
	Expect(pkts[1].DstPort).To(Equal(uint16(443)))
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
