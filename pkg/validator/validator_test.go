package validator_test

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/validator"
	. "github.com/onsi/gomega"
)

func TestValidateCIDR(t *testing.T) {
	RegisterTestingT(t)

	Expect(validator.ValidateCIDR("192.168.1.0/24")).To(BeTrue())
	Expect(validator.ValidateCIDR("10.0.0.0/8")).To(BeTrue())
	Expect(validator.ValidateCIDR("1.1.1.1/32")).To(BeTrue())
	Expect(validator.ValidateCIDR("2001:db8::/32")).To(BeTrue())

	Expect(validator.ValidateCIDR("not-a-cidr")).To(BeFalse())
	Expect(validator.ValidateCIDR("300.0.0.0/8")).To(BeFalse())
	Expect(validator.ValidateCIDR("")).To(BeFalse())
}

func TestValidateAction(t *testing.T) {
	RegisterTestingT(t)

	Expect(validator.ValidateAction("accept")).To(BeTrue())
	Expect(validator.ValidateAction("Accept")).To(BeTrue())
	Expect(validator.ValidateAction("ACCEPT")).To(BeTrue())
	Expect(validator.ValidateAction("drop")).To(BeTrue())
	Expect(validator.ValidateAction("Drop")).To(BeTrue())
	Expect(validator.ValidateAction("DROP")).To(BeTrue())

	Expect(validator.ValidateAction("")).To(BeFalse())
	Expect(validator.ValidateAction("deny")).To(BeFalse())
	Expect(validator.ValidateAction("invalid")).To(BeFalse())
}

func TestConfigValidateMissingDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{
		Rules: []config.Rule{
			{SrcNet: []string{"192.168.1.0/24"}, Action: "Accept"},
		},
	}
	Expect(c.DefaultAction).To(BeEmpty())
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid default_action"))
}

func TestConfigValidateInvalidDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{DefaultAction: "badaction"}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid default_action"))
}

func TestConfigValidateInvalidSrcNet(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{
		Rules: []config.Rule{
			{SrcNet: []string{"not-a-cidr"}, Action: "Accept"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid src_net"))
}

func TestConfigValidateInvalidDstNet(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{
		Rules: []config.Rule{
			{DstNet: []string{"bad-cidr"}, Action: "Drop"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid dst_net"))
}

func TestConfigValidateInvalidNotSrcNet(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{
		Rules: []config.Rule{
			{NotSrcNet: []string{"256.0.0.0/8"}, Action: "Drop"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid neg_src_net"))
}

func TestConfigValidateInvalidNotDstNet(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{
		Rules: []config.Rule{
			{NotDstNet: []string{"abc"}, Action: "Drop"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid neg_dst_net"))
}

func TestConfigValidateInvalidRuleAction(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{
		Rules: []config.Rule{
			{SrcNet: []string{"10.0.0.0/8"}, Action: "unknown"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid action"))
}

func TestValidateIP(t *testing.T) {
	RegisterTestingT(t)

	Expect(validator.ValidateIP("192.168.1.5")).To(BeTrue())
	Expect(validator.ValidateIP("10.0.0.1")).To(BeTrue())
	Expect(validator.ValidateIP("1.1.1.1")).To(BeTrue())
	Expect(validator.ValidateIP("2001:db8::1")).To(BeTrue())
	Expect(validator.ValidateIP("::1")).To(BeTrue())

	Expect(validator.ValidateIP("not-an-ip")).To(BeFalse())
	Expect(validator.ValidateIP("300.0.0.1")).To(BeFalse())
	Expect(validator.ValidateIP("192.168.1.0/24")).To(BeFalse())
	Expect(validator.ValidateIP("")).To(BeFalse())
}

func TestValidatePort(t *testing.T) {
	RegisterTestingT(t)

	Expect(validator.ValidatePort(0)).To(BeTrue())
	Expect(validator.ValidatePort(80)).To(BeTrue())
	Expect(validator.ValidatePort(443)).To(BeTrue())
	Expect(validator.ValidatePort(65535)).To(BeTrue())

	Expect(validator.ValidatePort(65536)).To(BeFalse())
	Expect(validator.ValidatePort(100000)).To(BeFalse())
}

func TestValidateProtocol(t *testing.T) {
	RegisterTestingT(t)

	Expect(validator.ValidateProtocol(0)).To(BeTrue())
	Expect(validator.ValidateProtocol(6)).To(BeTrue())  // TCP
	Expect(validator.ValidateProtocol(17)).To(BeTrue()) // UDP
	Expect(validator.ValidateProtocol(255)).To(BeTrue())

	Expect(validator.ValidateProtocol(256)).To(BeFalse())
	Expect(validator.ValidateProtocol(1000)).To(BeFalse())
}

func TestValidateStructFieldsRecursiveSlice(t *testing.T) {
	RegisterTestingT(t)

	type Inner struct {
		CIDR string `yaml:"cidr" validate:"isValidCIDR"`
	}
	type Outer struct {
		Items []Inner `yaml:"items"`
	}

	err := validator.ValidateStructFields(Outer{
		Items: []Inner{{CIDR: "not-a-cidr"}},
	})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("items[0]"))
	Expect(err.Error()).To(ContainSubstring("invalid cidr"))

	err = validator.ValidateStructFields(Outer{
		Items: []Inner{{CIDR: "192.168.1.0/24"}, {CIDR: "10.0.0.0/8"}},
	})
	Expect(err).To(BeNil())

	err = validator.ValidateStructFields(Outer{Items: nil})
	Expect(err).To(BeNil())
}

func TestConfigValidateInvalidSrcAddr(t *testing.T) {
	RegisterTestingT(t)

	pkts := &config.PacketConfig{
		Packets: []config.Packet{
			{SrcAddr: "not-an-ip", DstAddr: "1.1.1.1"},
		},
	}
	err := pkts.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid src_addr"))
}

func TestConfigValidateInvalidDstAddr(t *testing.T) {
	RegisterTestingT(t)

	pkts := &config.PacketConfig{
		Packets: []config.Packet{
			{SrcAddr: "192.168.1.1", DstAddr: "bad-ip"},
		},
	}
	err := pkts.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid dst_addr"))
}

func TestConfigValidateValidPackets(t *testing.T) {
	RegisterTestingT(t)

	pkts := &config.PacketConfig{
		Packets: []config.Packet{
			{SrcAddr: "192.168.1.5", DstAddr: "1.1.1.1"},
			{SrcAddr: "2001:db8::1", DstAddr: "2001:db8::2"},
		},
	}
	err := pkts.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateValid(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{
		Rules: []config.Rule{
			{
				SrcNet:    []string{"192.168.1.0/24"},
				DstNet:    []string{"1.1.1.1/32"},
				NotSrcNet: []string{"192.168.1.128/25"},
				NotDstNet: []string{"1.1.1.0/30"},
				Action:    "Accept",
			},
		},
		DefaultAction: "Drop",
	}
	err := c.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateInvalidPortTag(t *testing.T) {
	RegisterTestingT(t)

	type testStruct struct {
		Port uint `yaml:"port" validate:"isPortValid"`
	}

	err := validator.ValidateStructFields(testStruct{Port: 65535})
	Expect(err).To(BeNil())

	err = validator.ValidateStructFields(testStruct{Port: 65536})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid port"))
}

func TestConfigValidateInvalidProtoTag(t *testing.T) {
	RegisterTestingT(t)

	type testStruct struct {
		Proto uint `yaml:"proto" validate:"isProtoValid"`
	}

	err := validator.ValidateStructFields(testStruct{Proto: 255})
	Expect(err).To(BeNil())

	err = validator.ValidateStructFields(testStruct{Proto: 256})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid proto"))
}

func TestConfigValidatePortSliceTag(t *testing.T) {
	RegisterTestingT(t)

	type testStruct struct {
		Ports []uint `yaml:"ports" validate:"isPortValid"`
	}

	err := validator.ValidateStructFields(testStruct{Ports: []uint{80, 443, 65535}})
	Expect(err).To(BeNil())

	err = validator.ValidateStructFields(testStruct{Ports: []uint{80, 65536}})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid ports"))
}

func TestConfigValidateProtoSliceTag(t *testing.T) {
	RegisterTestingT(t)

	type testStruct struct {
		Protos []uint `yaml:"protos" validate:"isProtoValid"`
	}

	err := validator.ValidateStructFields(testStruct{Protos: []uint{6, 17, 255}})
	Expect(err).To(BeNil())

	err = validator.ValidateStructFields(testStruct{Protos: []uint{6, 256}})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid protos"))
}

func TestConfigValidateValidRuleWithPortsAndProto(t *testing.T) {
	RegisterTestingT(t)

	c := &config.RuleConfig{
		Rules: []config.Rule{
			{
				SrcNet:     []string{"192.168.1.0/24"},
				DstNet:     []string{"1.1.1.1/32"},
				Protocol:   []proto.Proto{proto.TCP, proto.UDP},
				SrcPort:    []uint16{30000},
				DstPort:    []uint16{80, 443},
				NotProto:   []proto.Proto{proto.ICMP},
				NotSrcPort: []uint16{22},
				NotDstPort: []uint16{8080},
				Action:     "Accept",
			},
		},
		DefaultAction: "Drop",
	}
	err := c.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateValidPacketWithPortAndProto(t *testing.T) {
	RegisterTestingT(t)

	pkts := &config.PacketConfig{
		Packets: []config.Packet{
			{SrcAddr: "192.168.1.5", DstAddr: "1.1.1.1", Proto: proto.TCP, SrcPort: 30000, DstPort: 80},
		},
	}
	err := pkts.Validate()
	Expect(err).To(BeNil())
}
