package engine

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	. "github.com/onsi/gomega"
)

const testRulesYAML = `
rules:
  - name: allow-192.168-to-1.1.1.1
    src_net: [192.168.1.0/24]
    dst_net: [1.1.1.1/32]
    dst_port: [80]
    src_port: [30000]
    proto: [7]
    action: Accept
  - name: deny-access-http
    dst_net: [1.1.1.1/32]
    dst_port: [80]
    proto: [7]
    action: Drop
  - name: deny-tcp-8080
    dst_net: [2.2.2.2/32]
    dst_port: [8080]
    proto: [7]
    action: Drop
default_action: Accept
`

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

const testSetsYAML = `
sets:
  - name: trusted-ips
    type: ip
    members:
      - 192.168.1.0/24
      - 10.0.0.0/8
  - name: web-ports
    type: port
    members:
      - "80"
      - "443"
      - "8080"
  - name: allowed-protos
    type: proto
    members:
      - tcp
      - udp
`

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	Expect(engine).ToNot(BeNil())
}

func TestPacketsFromBytesAndMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigRulesFromBytes([]byte(testRulesYAML))
	Expect(err).To(BeNil())

	pkts, err := config.PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())
	Expect(len(pkts)).To(Equal(5))

	// First packet: src 192.168.1.5 -> dst 1.1.1.1:80 proto 7, src_port 30000 — matches rule 1 (Accept)
	m := &match.Match{Packet: pkts[0]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))

	// Second packet: src 10.0.0.1 -> dst 2.2.2.2:8080 proto 7 — matches rule 3 (Drop)
	m = &match.Match{Packet: pkts[1]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Drop))

	// Third packet: proto 17, no matching rule — default action Accept
	m = &match.Match{Packet: pkts[2]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))
}

func TestLoadSetsFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigRulesFromBytes([]byte(testRulesYAML))
	Expect(err).To(BeNil())

	err = engine.ConfigSetsFromBytes([]byte(testSetsYAML))
	Expect(err).To(BeNil())

	sets := engine.Sets()
	Expect(sets).To(HaveLen(3))
	Expect(sets).To(HaveKey("trusted-ips"))
	Expect(sets).To(HaveKey("web-ports"))
	Expect(sets).To(HaveKey("allowed-protos"))
}

const testRulesWithSetsYAML = `
rules:
  - name: allow-trusted-to-web
    src_ip_set: trusted-ips
    dst_port_set: web-ports
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`

func TestRulesReferencingNamedSets(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})

	// Sets must be loaded before rules that reference them.
	err := engine.ConfigSetsFromBytes([]byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = engine.ConfigRulesFromBytes([]byte(testRulesWithSetsYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.table.Rules)).To(Equal(2))

	rule1 := engine.table.Rules[0]
	Expect(rule1.Source.IPSet).ToNot(BeNil())
	Expect(rule1.DstPortSet).ToNot(BeNil())
	Expect(rule1.Source.Net).To(BeNil())
	Expect(rule1.DstPort).To(BeNil())
}

func TestRulesReferencingUnknownSetError(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})

	// No sets loaded — referencing a set should return an error.
	err := engine.ConfigRulesFromBytes([]byte(testRulesWithSetsYAML))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
}

func TestRulesWithNamedSetsMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigSetsFromBytes([]byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = engine.ConfigRulesFromBytes([]byte(testRulesWithSetsYAML))
	Expect(err).To(BeNil())

	// Packet from trusted-ips (192.168.1.0/24) to web-ports (80,443,8080) → Accept
	pkts, err := config.PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())

	// First packet: src 192.168.1.5 dst 1.1.1.1:80 → matches rule 1 (Accept)
	m := &match.Match{Packet: pkts[0]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))

	// Second packet: src 10.0.0.1 dst 2.2.2.2:8080 → src is in trusted-ips (10.0.0.0/8),
	// dst port 8080 is in web-ports → matches rule 1 (Accept)
	m = &match.Match{Packet: pkts[1]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))

	// Third packet: src 172.16.0.1 → NOT in trusted-ips → falls through to deny-all (Drop)
	m = &match.Match{Packet: pkts[2]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Drop))
}

const testRulesWithNegSetsYAML = `
rules:
  - name: allow-non-blocked-src
    neg_src_ip_set: trusted-ips
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`

func TestRulesReferencingNegatedNamedSets(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigSetsFromBytes([]byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = engine.ConfigRulesFromBytes([]byte(testRulesWithNegSetsYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.table.Rules)).To(Equal(2))
	Expect(engine.table.Rules[0].NegSrcIPSet).ToNot(BeNil())
}

func TestRulesWithNegatedNamedSetsMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigSetsFromBytes([]byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = engine.ConfigRulesFromBytes([]byte(testRulesWithNegSetsYAML))
	Expect(err).To(BeNil())

	pkts, err := config.PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())

	// First packet: src 192.168.1.5 — in trusted-ips → negated, rule1 does NOT match → deny-all (Drop)
	m := &match.Match{Packet: pkts[0]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Drop))

	// Third packet: src 172.16.0.1 — NOT in trusted-ips → rule1 matches (Accept)
	m = &match.Match{Packet: pkts[2]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))
}

func TestRulesReferencingUnknownNegatedSetError(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	// No sets loaded — negated set reference must fail at load time.
	err := engine.ConfigRulesFromBytes([]byte(testRulesWithNegSetsYAML))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
}

func TestLoadRulesFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigRulesFromBytes([]byte(testRulesYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.table.Rules)).To(Equal(3))

	// Verify first rule
	rule1 := engine.table.Rules[0]
	Expect(rule1.Source.Net).ToNot(BeNil())
	Expect(rule1.Source.Net.String()).To(Equal("192.168.1.0/24"))
	Expect(rule1.DstNet).ToNot(BeNil())
	Expect(rule1.DstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(rule1.Proto).ToNot(BeNil())
	Expect(rule1.Proto.Match(proto.Proto(7))).To(BeTrue())
	Expect(rule1.Action.String()).To(Equal("Accept"))

	// Verify second rule
	rule2 := engine.table.Rules[1]
	Expect(rule2.DstNet).ToNot(BeNil())
	Expect(rule2.DstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(rule2.Proto).ToNot(BeNil())
	Expect(rule2.Proto.Match(proto.Proto(7))).To(BeTrue())
	Expect(rule2.Action.String()).To(Equal("Drop"))

	// Verify default action is set
	Expect(engine.table.DefaultAction.Action.String()).To(Equal("Accept"))
}
