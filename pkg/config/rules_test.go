package config

import (
	"testing"

	. "github.com/onsi/gomega"

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
		Name:       "test-rule",
		SrcIPSet:   "my-ips",
		DstIPSet:   "my-ips",
		SrcPortSet: "my-ports",
		DstPortSet: "my-ports",
		Action:     "Accept",
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
		Name:     "bad-rule",
		SrcIPSet: "nonexistent",
		Action:   "Accept",
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
		Name:     "bad-rule",
		DstIPSet: "nonexistent",
		Action:   "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownSrcPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:       "bad-rule",
		SrcPortSet: "nonexistent",
		Action:     "Accept",
	}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownDstPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{
		Name:       "bad-rule",
		DstPortSet: "nonexistent",
		Action:     "Accept",
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
    src_ip_set: trusted-ips
    dst_port_set: web-ports
    not_src_ip_set: blocked-ips
    not_dst_port_set: banned-ports
    action: Accept
default_action: Drop
`
	rc, err := RuleConfigFromBytes([]byte(yaml))
	Expect(err).To(BeNil())
	Expect(rc).ToNot(BeNil())
	Expect(rc.Rules).To(HaveLen(1))
	Expect(rc.Rules[0].SrcIPSet).To(Equal("trusted-ips"))
	Expect(rc.Rules[0].DstPortSet).To(Equal("web-ports"))
	Expect(rc.Rules[0].NotSrcIPSet).To(Equal("blocked-ips"))
	Expect(rc.Rules[0].NotDstPortSet).To(Equal("banned-ports"))
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
		Name:          "test-neg-rule",
		NotSrcIPSet:   "blocked-ips",
		NotDstIPSet:   "blocked-ips",
		NotSrcPortSet: "banned-ports",
		NotDstPortSet: "banned-ports",
		Action:        "Accept",
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

	r := &Rule{Name: "bad", NotSrcIPSet: "nonexistent", Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(err.Error()).To(ContainSubstring("nonexistent"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotDstIPSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotDstIPSet: "nonexistent", Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotSrcPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotSrcPortSet: "nonexistent", Action: "Accept"}
	mRule, err := r.ToRule(nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
	Expect(mRule).To(BeNil())
}

func TestToRuleWithUnknownNotDstPortSet(t *testing.T) {
	RegisterTestingT(t)

	r := &Rule{Name: "bad", NotDstPortSet: "nonexistent", Action: "Accept"}
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
