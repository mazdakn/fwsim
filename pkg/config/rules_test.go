package config

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/set"
)

func TestToRuleWithoutSets(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:   "allow-http",
		Action: "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.Name).To(Equal("allow-http"))
	Expect(mRule.Source.IPSet).To(BeNil())
	Expect(mRule.Destination.IPSet).To(BeNil())
	Expect(mRule.Source.PortSet).To(BeNil())
	Expect(mRule.Destination.PortSet).To(BeNil())
}

func TestToRuleWithValidSets(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("10.0.0.0/8")

	portSet := set.NewPortSet()
	_ = portSet.Add("80")

	sets := map[string]set.Set{
		"my-ips":   ipSet,
		"my-ports": portSet,
	}

	r := &Rule{
		Name:        "test-rule",
		Source:      Endpoint{IPSet: "my-ips", PortSet: "my-ports"},
		Destination: Endpoint{IPSet: "my-ips", PortSet: "my-ports"},
		Action:      "Accept",
	}
	mRule, err := r.ToRule(sets)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.Source.IPSet).To(Equal(sets["my-ips"]))
	Expect(mRule.Destination.IPSet).To(Equal(sets["my-ips"]))
	Expect(mRule.Source.PortSet).To(Equal(sets["my-ports"]))
	Expect(mRule.Destination.PortSet).To(Equal(sets["my-ports"]))
}

func TestToRuleWithUnknownSrcIPSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:   "bad-rule",
		Source: Endpoint{IPSet: "nonexistent"},
		Action: "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(err.Error()).To(ContainSubstring("nonexistent"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownDstIPSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:        "bad-rule",
		Destination: Endpoint{IPSet: "nonexistent"},
		Action:      "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownSrcPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:   "bad-rule",
		Source: Endpoint{PortSet: "nonexistent"},
		Action: "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownDstPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:        "bad-rule",
		Destination: Endpoint{PortSet: "nonexistent"},
		Action:      "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestRuleConfigFromBytesWithSetFields(t *testing.T) {
	RegisterTestingT(t)

	yaml := `
rules:
  - name: allow-trusted
    src:
      ip_set: trusted-ips
    dst:
      port_set: web-ports
    not_src:
      ip_set: blocked-ips
    not_dst:
      port_set: banned-ports
    action: Accept
default_action: Drop
`
	rc, err := RuleConfigFromBytes([]byte(yaml))
	Expect(err).To(BeNil())
	Expect(rc).ToNot(BeNil())
	Expect(rc.Rules).To(HaveLen(1))
	Expect(rc.Rules[0].Source.IPSet).To(Equal("trusted-ips"))
	Expect(rc.Rules[0].Destination.PortSet).To(Equal("web-ports"))
	Expect(rc.Rules[0].NotSource.IPSet).To(Equal("blocked-ips"))
	Expect(rc.Rules[0].NotDestination.PortSet).To(Equal("banned-ports"))
}

func TestToRuleWithValidNegatedSets(t *testing.T) {
	RegisterTestingT(t)

	ipSet := set.NewIPSet()
	_ = ipSet.Add("10.0.0.0/8")

	portSet := set.NewPortSet()
	_ = portSet.Add("80")

	sets := map[string]set.Set{
		"blocked-ips":  ipSet,
		"banned-ports": portSet,
	}

	r := &Rule{
		Name:           "test-neg-rule",
		NotSource:      Endpoint{IPSet: "blocked-ips", PortSet: "banned-ports"},
		NotDestination: Endpoint{IPSet: "blocked-ips", PortSet: "banned-ports"},
		Action:         "Accept",
	}
	mRule, err := r.ToRule(sets)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.NotSource.IPSet).To(Equal(sets["blocked-ips"]))
	Expect(mRule.NotDestination.IPSet).To(Equal(sets["blocked-ips"]))
	Expect(mRule.NotSource.PortSet).To(Equal(sets["banned-ports"]))
	Expect(mRule.NotDestination.PortSet).To(Equal(sets["banned-ports"]))
}

func TestToRuleWithUnknownNotSrcIPSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotSource: Endpoint{IPSet: "nonexistent"}, Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(err.Error()).To(ContainSubstring("nonexistent"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotDstIPSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotDestination: Endpoint{IPSet: "nonexistent"}, Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotSrcPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotSource: Endpoint{PortSet: "nonexistent"}, Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotDstPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotDestination: Endpoint{PortSet: "nonexistent"}, Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithoutNegatedSetsNilByDefault(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "allow-http", Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).To(BeNil())
	Expect(mRule.NotSource.IPSet).To(BeNil())
	Expect(mRule.NotDestination.IPSet).To(BeNil())
	Expect(mRule.NotSource.PortSet).To(BeNil())
	Expect(mRule.NotDestination.PortSet).To(BeNil())
}

func TestToRuleWithNameOnlyPorts(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name: "allow-http",
		Source: Endpoint{
			Port: []port.Port{{Name: "ssh"}},
		},
		Destination: Endpoint{
			Port: []port.Port{{Name: "http"}, {Name: "https"}},
		},
		Action: "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.Source.Port).ToNot(BeNil())
	Expect(mRule.Source.Port.Match(uint16(22))).To(BeTrue())
	Expect(mRule.Destination.Port).ToNot(BeNil())
	Expect(mRule.Destination.Port.Match(uint16(80))).To(BeTrue())
	Expect(mRule.Destination.Port.Match(uint16(443))).To(BeTrue())
	Expect(mRule.Destination.Port.Match(uint16(22))).To(BeFalse())
}
