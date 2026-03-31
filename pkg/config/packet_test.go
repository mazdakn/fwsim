package config

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestPacketsFromFile(t *testing.T) {
	RegisterTestingT(t)

	pkts, err := PacketsFromFile("../../hack/packets.yaml")
	Expect(err).To(BeNil())
	Expect(len(pkts)).To(Equal(5))

	// Verify first packet
	Expect(pkts[0].SrcAddr.String()).To(Equal("192.168.1.5"))
	Expect(pkts[0].DstAddr.String()).To(Equal("1.1.1.1"))
	Expect(pkts[0].Proto).To(Equal(uint8(7)))
	Expect(pkts[0].SrcPort).To(Equal(uint16(30000)))
	Expect(pkts[0].DstPort).To(Equal(uint16(80)))

	// Verify second packet
	Expect(pkts[1].SrcAddr.String()).To(Equal("10.0.0.1"))
	Expect(pkts[1].DstAddr.String()).To(Equal("2.2.2.2"))
	Expect(pkts[1].Proto).To(Equal(uint8(7)))
	Expect(pkts[1].SrcPort).To(Equal(uint16(12345)))
	Expect(pkts[1].DstPort).To(Equal(uint16(8080)))
}

func TestPacketsFromFileMissing(t *testing.T) {
	RegisterTestingT(t)

	pkts, err := PacketsFromFile("nonexistent.yaml")
	Expect(err).ToNot(BeNil())
	Expect(pkts).To(BeNil())
}
