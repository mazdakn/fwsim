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
	Expect(mRule.Source.Sets).To(BeEmpty())
	Expect(mRule.Destination.Sets).To(BeEmpty())
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
		Source:      Endpoint{Sets: []string{"my-ips", "my-ports"}},
		Destination: Endpoint{Sets: []string{"my-ips", "my-ports"}},
		Action:      "Accept",
	}
	mRule, err := r.ToRule(sets)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.Source.Sets).To(HaveLen(2))
	Expect(mRule.Destination.Sets).To(HaveLen(2))
	Expect(mRule.Source.Sets[0]).To(Equal(sets["my-ips"]))
	Expect(mRule.Source.Sets[1]).To(Equal(sets["my-ports"]))
	Expect(mRule.Destination.Sets[0]).To(Equal(sets["my-ips"]))
	Expect(mRule.Destination.Sets[1]).To(Equal(sets["my-ports"]))
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
		Source: Endpoint{Sets: []string{"nonexistent"}},
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
		Destination: Endpoint{Sets: []string{"nonexistent"}},
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
		Source: Endpoint{Sets: []string{"nonexistent"}},
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
		Destination: Endpoint{Sets: []string{"nonexistent"}},
		Action:      "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestTableFromBytesWithSetFields(t *testing.T) {
	RegisterTestingT(t)

	yaml := `
name: main
rules:
  - name: allow-trusted
    src:
      sets: [trusted-ips, src-ipports]
    dst:
      sets: [web-ports, dst-ipports]
    not_src:
      sets: [blocked-ips, blocked-src-ipports]
    not_dst:
      sets: [banned-ports, blocked-dst-ipports]
    action: Accept
default_action: Drop
`
	rc, err := TableFromBytes([]byte(yaml))
	Expect(err).To(BeNil())
	Expect(rc).ToNot(BeNil())
	Expect(rc.Rules).To(HaveLen(1))
	Expect(rc.Rules[0].Source.Sets).To(Equal([]string{"trusted-ips", "src-ipports"}))
	Expect(rc.Rules[0].Destination.Sets).To(Equal([]string{"web-ports", "dst-ipports"}))
	Expect(rc.Rules[0].NotSource.Sets).To(Equal([]string{"blocked-ips", "blocked-src-ipports"}))
	Expect(rc.Rules[0].NotDestination.Sets).To(Equal([]string{"banned-ports", "blocked-dst-ipports"}))
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
		NotSource:      Endpoint{Sets: []string{"blocked-ips", "banned-ports"}},
		NotDestination: Endpoint{Sets: []string{"blocked-ips", "banned-ports"}},
		Action:         "Accept",
	}
	mRule, err := r.ToRule(sets)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.NotSource.Sets).To(HaveLen(2))
	Expect(mRule.NotDestination.Sets).To(HaveLen(2))
	Expect(mRule.NotSource.Sets[0]).To(Equal(sets["blocked-ips"]))
	Expect(mRule.NotSource.Sets[1]).To(Equal(sets["banned-ports"]))
	Expect(mRule.NotDestination.Sets[0]).To(Equal(sets["blocked-ips"]))
	Expect(mRule.NotDestination.Sets[1]).To(Equal(sets["banned-ports"]))
}

func TestToRuleWithUnknownNotSrcIPSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotSource: Endpoint{Sets: []string{"nonexistent"}}, Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(err.Error()).To(ContainSubstring("nonexistent"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotDstIPSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotDestination: Endpoint{Sets: []string{"nonexistent"}}, Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotSrcPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotSource: Endpoint{Sets: []string{"nonexistent"}}, Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotDstPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotDestination: Endpoint{Sets: []string{"nonexistent"}}, Action: "Accept"}
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
	Expect(mRule.NotSource.Sets).To(BeEmpty())
	Expect(mRule.NotDestination.Sets).To(BeEmpty())
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
		Source:         Endpoint{Sets: []string{"svc-tuples"}},
		Destination:    Endpoint{Sets: []string{"svc-tuples"}},
		NotSource:      Endpoint{Sets: []string{"svc-tuples"}},
		NotDestination: Endpoint{Sets: []string{"svc-tuples"}},
		Action:         "Accept",
	}
	mRule, err := r.ToRule(sets)
	Expect(err).To(BeNil())
	Expect(mRule).ToNot(BeNil())
	Expect(mRule.Source.Sets).To(Equal([]set.Set{sets["svc-tuples"]}))
	Expect(mRule.Destination.Sets).To(Equal([]set.Set{sets["svc-tuples"]}))
	Expect(mRule.NotSource.Sets).To(Equal([]set.Set{sets["svc-tuples"]}))
	Expect(mRule.NotDestination.Sets).To(Equal([]set.Set{sets["svc-tuples"]}))
}

func TestToRuleWithUnknownIPPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:           "bad",
		Source:         Endpoint{Sets: []string{"missing"}},
		Destination:    Endpoint{Sets: []string{"missing"}},
		NotSource:      Endpoint{Sets: []string{"missing"}},
		NotDestination: Endpoint{Sets: []string{"missing"}},
		Action:         "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestTableFromBytesAcceptsPassDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	yaml := `
name: main
rules:
  - name: continue-http
    action: Pass
default_action: Pass
`
	rc, err := TableFromBytes([]byte(yaml))
	Expect(err).To(BeNil())
	Expect(rc).ToNot(BeNil())
	Expect(rc.DefaultAction).To(Equal("Pass"))
}
