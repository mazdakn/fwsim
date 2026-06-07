package validator_test

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
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
	Expect(validator.ValidateAction("pass")).To(BeTrue())
	Expect(validator.ValidateAction("Pass")).To(BeTrue())
	Expect(validator.ValidateAction("PASS")).To(BeTrue())

	Expect(validator.ValidateAction("")).To(BeFalse())
	Expect(validator.ValidateAction("deny")).To(BeFalse())
	Expect(validator.ValidateAction("invalid")).To(BeFalse())
}

func TestConfigValidateMissingDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{Source: config.Endpoint{Net: []string{"192.168.1.0/24"}}, Action: "Accept"},
			}},
		},
	}
	Expect(c.DefaultAction).To(BeEmpty())
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid default_action"))
}

func TestConfigValidateInvalidDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main", DefaultAction: "badaction"}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid default_action"))
}

func TestConfigValidatePassDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main", DefaultAction: "Pass"}
	err := c.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateInvalidSrcNet(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{Source: config.Endpoint{Net: []string{"not-a-cidr"}}, Action: "Accept"},
			}},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("src: invalid net"))
}

func TestConfigValidateInvalidDstNet(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{Destination: config.Endpoint{Net: []string{"bad-cidr"}}, Action: "Drop"},
			}},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("dst: invalid net"))
}

func TestConfigValidateInvalidNotSrcNet(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{NotSource: config.Endpoint{Net: []string{"256.0.0.0/8"}}, Action: "Drop"},
			}},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("not_src: invalid net"))
}

func TestConfigValidateInvalidNotDstNet(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{NotDestination: config.Endpoint{Net: []string{"abc"}}, Action: "Drop"},
			}},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("not_dst: invalid net"))
}

func TestConfigValidateInvalidRuleAction(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{Source: config.Endpoint{Net: []string{"10.0.0.0/8"}}, Action: "unknown"},
			}},
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

func TestValidatePortValue(t *testing.T) {
	RegisterTestingT(t)

	// Numeric ports (Name empty) are always valid
	Expect(validator.ValidatePortValue(port.Port{Number: 0})).To(BeTrue())
	Expect(validator.ValidatePortValue(port.Port{Number: 80})).To(BeTrue())
	Expect(validator.ValidatePortValue(port.Port{Number: 65535})).To(BeTrue())

	// Well-known port names are valid
	Expect(validator.ValidatePortValue(port.Port{Number: 80, Name: "http"})).To(BeTrue())
	Expect(validator.ValidatePortValue(port.Port{Number: 443, Name: "https"})).To(BeTrue())
	Expect(validator.ValidatePortValue(port.Port{Number: 22, Name: "ssh"})).To(BeTrue())

	// Unknown names are invalid, even when a valid Number is also set — the
	// Name field takes precedence during validation.
	Expect(validator.ValidatePortValue(port.Port{Name: "notaservice"})).To(BeFalse())
	Expect(validator.ValidatePortValue(port.Port{Name: "badport"})).To(BeFalse())
	Expect(validator.ValidatePortValue(port.Port{Number: 80, Name: "badservice"})).To(BeFalse())
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

func TestValidateSetType(t *testing.T) {
	RegisterTestingT(t)

	Expect(validator.ValidateSetType("ip")).To(BeTrue())
	Expect(validator.ValidateSetType("port")).To(BeTrue())
	Expect(validator.ValidateSetType("proto")).To(BeTrue())
	Expect(validator.ValidateSetType("ipport")).To(BeTrue())
	Expect(validator.ValidateSetType("bad")).To(BeFalse())
}

func TestValidateConnState(t *testing.T) {
	RegisterTestingT(t)

	Expect(validator.ValidateConnState("new")).To(BeTrue())
	Expect(validator.ValidateConnState("ESTABLISHED")).To(BeTrue())
	Expect(validator.ValidateConnState("related")).To(BeFalse())
	Expect(validator.ValidateConnState("")).To(BeFalse())
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

func TestValidateStructFieldsRecursiveStruct(t *testing.T) {
	RegisterTestingT(t)

	type Inner struct {
		CIDR string `yaml:"cidr" validate:"isValidCIDR"`
	}
	type Outer struct {
		Inner Inner `yaml:"inner"`
	}

	err := validator.ValidateStructFields(Outer{
		Inner: Inner{CIDR: "not-a-cidr"},
	})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("inner: invalid cidr"))

	err = validator.ValidateStructFields(Outer{
		Inner: Inner{CIDR: "192.168.1.0/24"},
	})
	Expect(err).To(BeNil())
}

func TestConfigValidateInvalidSrcAddr(t *testing.T) {
	RegisterTestingT(t)

	pkt := &config.Packet{SrcAddr: "not-an-ip", DstAddr: "1.1.1.1"}
	err := pkt.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid src_addr"))
}

func TestConfigValidateInvalidDstAddr(t *testing.T) {
	RegisterTestingT(t)

	pkt := &config.Packet{SrcAddr: "192.168.1.1", DstAddr: "bad-ip"}
	err := pkt.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid dst_addr"))
}

func TestConfigValidateValidPackets(t *testing.T) {
	RegisterTestingT(t)

	err := (&config.Packet{SrcAddr: "192.168.1.5", DstAddr: "1.1.1.1"}).Validate()
	Expect(err).To(BeNil())

	err = (&config.Packet{SrcAddr: "2001:db8::1", DstAddr: "2001:db8::2"}).Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateValid(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{
					Source:         config.Endpoint{Net: []string{"192.168.1.0/24"}},
					Destination:    config.Endpoint{Net: []string{"1.1.1.1/32"}},
					NotSource:      config.Endpoint{Net: []string{"192.168.1.128/25"}},
					NotDestination: config.Endpoint{Net: []string{"1.1.1.0/30"}},
					Action:         "Accept",
				},
			}},
		},
		DefaultAction: "Drop",
	}
	err := c.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateInvalidConnState(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{
		Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{ConnState: []string{"invalid"}, Action: "Accept"},
			}},
		},
		DefaultAction: "Drop",
	}

	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid ct_state"))
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

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{
					Source:         config.Endpoint{Net: []string{"192.168.1.0/24"}, Port: []port.Port{{Number: 30000}}},
					Destination:    config.Endpoint{Net: []string{"1.1.1.1/32"}, Port: []port.Port{{Number: 80}, {Number: 443}}},
					Protocol:       []proto.Proto{proto.TCP, proto.UDP},
					NotProto:       []proto.Proto{proto.ICMP},
					NotSource:      config.Endpoint{Port: []port.Port{{Number: 22}}},
					NotDestination: config.Endpoint{Port: []port.Port{{Number: 8080}}},
					Action:         "Accept",
				},
			}},
		},
		DefaultAction: "Drop",
	}
	err := c.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateValidRuleWithNamedPorts(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{
					Source:      config.Endpoint{Port: []port.Port{{Number: 22, Name: "ssh"}}},
					Destination: config.Endpoint{Port: []port.Port{{Number: 80, Name: "http"}, {Number: 443, Name: "https"}}},
					Action:      "Accept",
				},
			}},
		},
		DefaultAction: "Drop",
	}
	err := c.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateRuleWithInvalidPortName(t *testing.T) {
	RegisterTestingT(t)

	c := &config.Table{Name: "main",
		Chains: []config.Chain{
			{Name: "default", Rules: []config.Rule{
				{
					Destination: config.Endpoint{Port: []port.Port{{Name: "notaservice"}}},
					Action:      "Accept",
				},
			}},
		},
		DefaultAction: "Drop",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid port"))
}

func TestConfigValidateValidPacketWithPortAndProto(t *testing.T) {
	RegisterTestingT(t)

	pkt := &config.Packet{SrcAddr: "192.168.1.5", DstAddr: "1.1.1.1", Proto: proto.TCP, SrcPort: port.Port{Number: 30000}, DstPort: port.Port{Number: 80}}
	err := pkt.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateValidPacketWithNamedPort(t *testing.T) {
	RegisterTestingT(t)

	pkt := &config.Packet{SrcAddr: "192.168.1.5", DstAddr: "1.1.1.1", Proto: proto.TCP, SrcPort: port.Port{Number: 12345}, DstPort: port.Port{Number: 443, Name: "https"}}
	err := pkt.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidatePacketWithInvalidPortName(t *testing.T) {
	RegisterTestingT(t)

	pkt := &config.Packet{SrcAddr: "192.168.1.5", DstAddr: "1.1.1.1", DstPort: port.Port{Name: "badservice"}}
	err := pkt.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid dst_port"))
}
