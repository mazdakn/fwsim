package config

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/rule"
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

func TestToRuleWithPassAction(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:   "continue-http",
		Action: "Pass",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.Action).To(Equal(rule.Pass))
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
      ipport_set: src-ipports
    dst:
      port_set: web-ports
      ipport_set: dst-ipports
    not_src:
      ip_set: blocked-ips
      ipport_set: blocked-src-ipports
    not_dst:
      port_set: banned-ports
      ipport_set: blocked-dst-ipports
    action: Accept
default_action: Drop
`
	rc, err := RuleConfigFromBytes([]byte(yaml))
	Expect(err).To(BeNil())
	Expect(rc).ToNot(BeNil())
	Expect(rc.Rules).To(HaveLen(1))
	Expect(rc.Rules[0].Source.IPSet).To(Equal("trusted-ips"))
	Expect(rc.Rules[0].Source.IPPortSet).To(Equal("src-ipports"))
	Expect(rc.Rules[0].Destination.PortSet).To(Equal("web-ports"))
	Expect(rc.Rules[0].Destination.IPPortSet).To(Equal("dst-ipports"))
	Expect(rc.Rules[0].NotSource.IPSet).To(Equal("blocked-ips"))
	Expect(rc.Rules[0].NotSource.IPPortSet).To(Equal("blocked-src-ipports"))
	Expect(rc.Rules[0].NotDestination.PortSet).To(Equal("banned-ports"))
	Expect(rc.Rules[0].NotDestination.IPPortSet).To(Equal("blocked-dst-ipports"))
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

func TestToRuleWithValidIPPortSets(t *testing.T) {
	RegisterTestingT(t)

	ipPortSet := set.NewIPPortSet()
	_ = ipPortSet.Add("10.0.0.0/8,80")

	sets := map[string]set.Set{
		"svc-tuples": ipPortSet,
	}

	r := &Rule{
		Name:           "tuple-rule",
		Source:         Endpoint{IPPortSet: "svc-tuples"},
		Destination:    Endpoint{IPPortSet: "svc-tuples"},
		NotSource:      Endpoint{IPPortSet: "svc-tuples"},
		NotDestination: Endpoint{IPPortSet: "svc-tuples"},
		Action:         "Accept",
	}
	mRule, err := r.ToRule(sets)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.Source.IPPortSet).To(Equal(sets["svc-tuples"]))
	Expect(mRule.Destination.IPPortSet).To(Equal(sets["svc-tuples"]))
	Expect(mRule.NotSource.IPPortSet).To(Equal(sets["svc-tuples"]))
	Expect(mRule.NotDestination.IPPortSet).To(Equal(sets["svc-tuples"]))
}

func TestToRuleWithUnknownIPPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:           "bad",
		Source:         Endpoint{IPPortSet: "missing"},
		Destination:    Endpoint{IPPortSet: "missing"},
		NotSource:      Endpoint{IPPortSet: "missing"},
		NotDestination: Endpoint{IPPortSet: "missing"},
		Action:         "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestRuleConfigFromBytesRejectsPassDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	yaml := `
rules:
  - name: continue-http
    action: Pass
default_action: Pass
`
	rc, err := RuleConfigFromBytes([]byte(yaml))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("invalid default_action"))
	Expect(rc).To(BeNil())
}
