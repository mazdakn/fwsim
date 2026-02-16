package config

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestRuleYAMLStruct(t *testing.T) {
	RegisterTestingT(t)

	proto := uint8(17)
	srcPort := uint16(55555)
	dstPort := uint16(53)

	ry := RuleYAML{
		SrcNet:   "10.10.10.0/24",
		DstNet:   "1.1.1.1/32",
		Protocol: &proto,
		SrcPort:  &srcPort,
		DstPort:  &dstPort,
		Action:   "Accept",
	}

	Expect(ry.SrcNet).To(Equal("10.10.10.0/24"))
	Expect(ry.DstNet).To(Equal("1.1.1.1/32"))
	Expect(*ry.Protocol).To(Equal(proto))
	Expect(*ry.SrcPort).To(Equal(srcPort))
	Expect(*ry.DstPort).To(Equal(dstPort))
	Expect(ry.Action).To(Equal("Accept"))
}

func TestParseRuleYAML(t *testing.T) {
	RegisterTestingT(t)

	proto := uint8(17)
	srcPort := uint16(55555)
	dstPort := uint16(53)

	ry := &RuleYAML{
		SrcNet:   "10.10.10.0/24",
		DstNet:   "1.1.1.1/32",
		Protocol: &proto,
		SrcPort:  &srcPort,
		DstPort:  &dstPort,
		Action:   "Accept",
	}

	srcNet, dstNet, protocol, sp, dp, actionStr, err := ParseRuleYAML(ry)
	Expect(err).ToNot(HaveOccurred())

	Expect(srcNet).ToNot(BeNil())
	Expect(srcNet.String()).To(Equal("10.10.10.0/24"))
	Expect(dstNet).ToNot(BeNil())
	Expect(dstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(protocol).ToNot(BeNil())
	Expect(*protocol).To(Equal(proto))
	Expect(sp).ToNot(BeNil())
	Expect(*sp).To(Equal(srcPort))
	Expect(dp).ToNot(BeNil())
	Expect(*dp).To(Equal(dstPort))
	Expect(actionStr).To(Equal("Accept"))
}

func TestParseRuleYAMLInvalidSrcNet(t *testing.T) {
	RegisterTestingT(t)

	ry := &RuleYAML{
		SrcNet: "invalid-cidr",
	}

	_, _, _, _, _, _, err := ParseRuleYAML(ry)
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("invalid src_net"))
}

func TestParseRuleYAMLInvalidDstNet(t *testing.T) {
	RegisterTestingT(t)

	ry := &RuleYAML{
		DstNet: "invalid-cidr",
	}

	_, _, _, _, _, _, err := ParseRuleYAML(ry)
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("invalid dst_net"))
}
