package config

import (
	"testing"

	"github.com/mazdakn/fwsim/internal"
	"github.com/mazdakn/fwsim/internal/packet"
	. "github.com/onsi/gomega"
)

func TestNewConfigValidatorSuccess(t *testing.T) {
	RegisterTestingT(t)

	v, err := newConfigValidator()
	Expect(err).To(BeNil())
	Expect(v).ToNot(BeNil())
}

func TestConfigValidatorValidateCIDR(t *testing.T) {
	RegisterTestingT(t)

	v, err := newConfigValidator()
	Expect(err).To(BeNil())

	Expect(v.validateCIDR("192.168.1.0/24")).To(BeTrue())
	Expect(v.validateCIDR("10.0.0.0/8")).To(BeTrue())
	Expect(v.validateCIDR("1.1.1.1/32")).To(BeTrue())
	Expect(v.validateCIDR("2001:db8::/32")).To(BeTrue())

	Expect(v.validateCIDR("not-a-cidr")).To(BeFalse())
	Expect(v.validateCIDR("300.0.0.0/8")).To(BeFalse())
	Expect(v.validateCIDR("")).To(BeFalse())
}

func TestConfigValidatorValidateAction(t *testing.T) {
	RegisterTestingT(t)

	v, err := newConfigValidator()
	Expect(err).To(BeNil())

	Expect(v.validateAction("accept")).To(BeTrue())
	Expect(v.validateAction("Accept")).To(BeTrue())
	Expect(v.validateAction("ACCEPT")).To(BeTrue())
	Expect(v.validateAction("drop")).To(BeTrue())
	Expect(v.validateAction("Drop")).To(BeTrue())
	Expect(v.validateAction("DROP")).To(BeTrue())

	Expect(v.validateAction("")).To(BeFalse())
	Expect(v.validateAction("deny")).To(BeFalse())
	Expect(v.validateAction("invalid")).To(BeFalse())
}

func TestConfigValidateMissingDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	c := &Config{
		Rules: []model.RuleConfig{
			{SrcNet: []string{"192.168.1.0/24"}, Action: "Accept"},
		},
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("default_action is required"))
}

func TestConfigValidateInvalidDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	c := &Config{DefaultAction: "badaction"}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid default_action"))
}

func TestConfigValidateInvalidSrcNet(t *testing.T) {
	RegisterTestingT(t)

	c := &Config{
		Rules: []model.RuleConfig{
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

	c := &Config{
		Rules: []model.RuleConfig{
			{DstNet: []string{"bad-cidr"}, Action: "Drop"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid dst_net"))
}

func TestConfigValidateInvalidNegSrcNet(t *testing.T) {
	RegisterTestingT(t)

	c := &Config{
		Rules: []model.RuleConfig{
			{NegSrcNet: []string{"256.0.0.0/8"}, Action: "Drop"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid neg_src_net"))
}

func TestConfigValidateInvalidNegDstNet(t *testing.T) {
	RegisterTestingT(t)

	c := &Config{
		Rules: []model.RuleConfig{
			{NegDstNet: []string{"abc"}, Action: "Drop"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid neg_dst_net"))
}

func TestConfigValidateInvalidRuleAction(t *testing.T) {
	RegisterTestingT(t)

	c := &Config{
		Rules: []model.RuleConfig{
			{SrcNet: []string{"10.0.0.0/8"}, Action: "unknown"},
		},
		DefaultAction: "Accept",
	}
	err := c.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid action"))
}

func TestConfigValidatorValidateIP(t *testing.T) {
	RegisterTestingT(t)

	v, err := newConfigValidator()
	Expect(err).To(BeNil())

	Expect(v.validateIP("192.168.1.5")).To(BeTrue())
	Expect(v.validateIP("10.0.0.1")).To(BeTrue())
	Expect(v.validateIP("1.1.1.1")).To(BeTrue())
	Expect(v.validateIP("2001:db8::1")).To(BeTrue())
	Expect(v.validateIP("::1")).To(BeTrue())

	Expect(v.validateIP("not-an-ip")).To(BeFalse())
	Expect(v.validateIP("300.0.0.1")).To(BeFalse())
	Expect(v.validateIP("192.168.1.0/24")).To(BeFalse())
	Expect(v.validateIP("")).To(BeFalse())
}

func TestConfigValidateInvalidSrcAddr(t *testing.T) {
	RegisterTestingT(t)

	pkts := &PacketsConfig{
		Packets: []packet.PacketConfig{
			{SrcAddr: "not-an-ip", DstAddr: "1.1.1.1"},
		},
	}
	err := pkts.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid src_addr"))
}

func TestConfigValidateInvalidDstAddr(t *testing.T) {
	RegisterTestingT(t)

	pkts := &PacketsConfig{
		Packets: []packet.PacketConfig{
			{SrcAddr: "192.168.1.1", DstAddr: "bad-ip"},
		},
	}
	err := pkts.Validate()
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid dst_addr"))
}

func TestConfigValidateValidPackets(t *testing.T) {
	RegisterTestingT(t)

	pkts := &PacketsConfig{
		Packets: []packet.PacketConfig{
			{SrcAddr: "192.168.1.5", DstAddr: "1.1.1.1"},
			{SrcAddr: "2001:db8::1", DstAddr: "2001:db8::2"},
		},
	}
	err := pkts.Validate()
	Expect(err).To(BeNil())
}

func TestConfigValidateValid(t *testing.T) {
	RegisterTestingT(t)

	c := &Config{
		Rules: []model.RuleConfig{
			{
				SrcNet:    []string{"192.168.1.0/24"},
				DstNet:    []string{"1.1.1.1/32"},
				NegSrcNet: []string{"192.168.1.128/25"},
				NegDstNet: []string{"1.1.1.0/30"},
				Action:    "Accept",
			},
		},
		DefaultAction: "Drop",
	}
	err := c.Validate()
	Expect(err).To(BeNil())
}
