package engine_test

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/config"
	enginepkg "github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/set"
	. "github.com/onsi/gomega"
)

func loadRulesFromBytes(e *enginepkg.Engine, data []byte) error {
	tbl, err := config.ConfigTableFromBytes(data, e.Sets())
	if err != nil {
		return err
	}
	e.SetTable(tbl)
	return nil
}

func loadSetsFromBytes(e *enginepkg.Engine, data []byte) error {
	sets, err := config.ConfigSetsFromBytes(data)
	if err != nil {
		return err
	}
	merged := e.Sets()
	if merged == nil {
		merged = map[string]set.Set{}
	}
	for name, s := range sets {
		merged[name] = s
	}
	e.SetSets(merged)
	return nil
}

const testRulesYAML = `
name: main
rules:
  - name: allow-192.168-to-1.1.1.1
    src:
      net: [192.168.1.0/24]
      port: [30000]
    dst:
      net: [1.1.1.1/32]
      port: [80]
    proto: [7]
    action: Accept
  - name: deny-access-http
    dst:
      net: [1.1.1.1/32]
      port: [80]
    proto: [7]
    action: Drop
  - name: deny-tcp-8080
    dst:
      net: [2.2.2.2/32]
      port: [8080]
    proto: [7]
    action: Drop
default_action: Accept
`

const testPacketsYAML = `
metadata:
  name: access backend
src_addr: 192.168.1.5
dst_addr: 1.1.1.1
proto: 7
src_port: 30000
dst_port: 80
`

const testPackets2YAML = `
metadata:
  name: access app1
src_addr: 10.0.0.1
dst_addr: 2.2.2.2
proto: 7
src_port: 12345
dst_port: 8080
`

const testPackets3YAML = `
metadata:
  name: dns traffic
src_addr: 172.16.0.1
dst_addr: 8.8.8.8
proto: 17
src_port: 54321
dst_port: 53
`

const testSetsYAML = `
name: trusted-ips
type: ip
members:
  - 192.168.1.0/24
  - 10.0.0.0/8
`

const testWebPortsSetYAML = `
name: web-ports
type: port
members:
  - "80"
  - "443"
  - "8080"
`

const testAllowedProtosSetYAML = `
name: allowed-protos
type: proto
members:
  - tcp
  - udp
`

const testRulesNamedPortYAML = `
name: main
rules:
  - name: allow-http
    dst:
      port: [http]
    proto: [6]
    action: Accept
  - name: allow-https
    dst:
      port: [https]
    proto: [6]
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`

const testPacketsNamedPortYAML = `
metadata:
  name: http to 1.1.1.1
src_addr: 192.168.1.5
dst_addr: 1.1.1.1
proto: 6
src_port: 30000
dst_port: http
`

const testPacketsNamedPort2YAML = `
metadata:
  name: https to 2.2.2.2
src_addr: 10.0.0.1
dst_addr: 2.2.2.2
proto: 6
src_port: 12345
dst_port: https
`

const testPacketsNamedPort3YAML = `
metadata:
  name: dns traffic
src_addr: 172.16.0.1
dst_addr: 8.8.8.8
proto: 17
src_port: 54321
dst_port: dns
`

func TestEngineWithNamedPortsInRulesAndPackets(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	err := loadRulesFromBytes(engine, []byte(testRulesNamedPortYAML))
	Expect(err).To(BeNil())

	pkt1, err := config.PacketsFromBytes([]byte(testPacketsNamedPortYAML))
	Expect(err).To(BeNil())
	pkt2, err := config.PacketsFromBytes([]byte(testPacketsNamedPort2YAML))
	Expect(err).To(BeNil())
	pkt3, err := config.PacketsFromBytes([]byte(testPacketsNamedPort3YAML))
	Expect(err).To(BeNil())

	// Packet to port "http" (80) → matches allow-http rule (Accept)
	m := &match.MatchContext{Packet: pkt1[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))

	// Packet to port "https" (443) → matches allow-https rule (Accept)
	m = &match.MatchContext{Packet: pkt2[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))

	// Packet to port "dns" (53) with proto 17 → no matching rule → deny-all (Drop)
	m = &match.MatchContext{Packet: pkt3[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Drop))
}

const testSetsNamedPortYAML = `
name: named-web-ports
type: port
members:
  - http
  - https
  - ssh
`

func TestEngineWithNamedPortsInSets(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()

	err := loadSetsFromBytes(engine, []byte(testSetsNamedPortYAML))
	Expect(err).To(BeNil())

	const rulesWithNamedPortSetYAML = `
name: main
rules:
  - name: allow-named-web
    dst:
      sets: [named-web-ports]
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`
	err = loadRulesFromBytes(engine, []byte(rulesWithNamedPortSetYAML))
	Expect(err).To(BeNil())

	pkt1, err := config.PacketsFromBytes([]byte(testPacketsNamedPortYAML))
	Expect(err).To(BeNil())
	pkt2, err := config.PacketsFromBytes([]byte(testPacketsNamedPort2YAML))
	Expect(err).To(BeNil())
	pkt3, err := config.PacketsFromBytes([]byte(testPacketsNamedPort3YAML))
	Expect(err).To(BeNil())

	// Packet to port "http" (80) → in named-web-ports → Accept
	m := &match.MatchContext{Packet: pkt1[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))

	// Packet to port "https" (443) → in named-web-ports → Accept
	m = &match.MatchContext{Packet: pkt2[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))

	// Packet to port "dns" (53) → NOT in named-web-ports → deny-all (Drop)
	m = &match.MatchContext{Packet: pkt3[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Drop))
}

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	Expect(engine).ToNot(BeNil())
}

func TestPacketsFromBytesAndMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	err := loadRulesFromBytes(engine, []byte(testRulesYAML))
	Expect(err).To(BeNil())

	pkt1, err := config.PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())
	pkt2, err := config.PacketsFromBytes([]byte(testPackets2YAML))
	Expect(err).To(BeNil())
	pkt3, err := config.PacketsFromBytes([]byte(testPackets3YAML))
	Expect(err).To(BeNil())

	// First packet: src 192.168.1.5 -> dst 1.1.1.1:80 proto 7, src_port 30000 — matches rule 1 (Accept)
	m := &match.MatchContext{Packet: pkt1[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))

	// Second packet: src 10.0.0.1 -> dst 2.2.2.2:8080 proto 7 — matches rule 3 (Drop)
	m = &match.MatchContext{Packet: pkt2[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Drop))

	// Third packet: proto 17, no matching rule — default action Accept
	m = &match.MatchContext{Packet: pkt3[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))
}

func TestLoadSetsFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	err := loadRulesFromBytes(engine, []byte(testRulesYAML))
	Expect(err).To(BeNil())

	err = loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())
	err = loadSetsFromBytes(engine, []byte(testWebPortsSetYAML))
	Expect(err).To(BeNil())
	err = loadSetsFromBytes(engine, []byte(testAllowedProtosSetYAML))
	Expect(err).To(BeNil())

	sets := engine.Sets()
	Expect(sets).To(HaveLen(3))
	Expect(sets).To(HaveKey("trusted-ips"))
	Expect(sets).To(HaveKey("web-ports"))
	Expect(sets).To(HaveKey("allowed-protos"))
}

const testRulesWithSetsYAML = `
name: main
rules:
  - name: allow-trusted-to-web
    src:
      sets: [trusted-ips]
    dst:
      sets: [web-ports]
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`

func TestRulesReferencingNamedSets(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()

	// Sets must be loaded before rules that reference them.
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())
	err = loadSetsFromBytes(engine, []byte(testWebPortsSetYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.Table().Rules)).To(Equal(2))

	rule1 := engine.Table().Rules[0]
	Expect(rule1.Source.Sets).To(HaveLen(1))
	Expect(rule1.Destination.Sets).To(HaveLen(1))
	Expect(rule1.Source.Net).To(BeNil())
	Expect(rule1.Destination.Port).To(BeNil())
}

func TestRulesReferencingUnknownSetError(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()

	// No sets loaded — referencing a set should return an error.
	err := loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
}

func TestRulesWithNamedSetsMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())
	err = loadSetsFromBytes(engine, []byte(testWebPortsSetYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).To(BeNil())

	// Packet from trusted-ips (192.168.1.0/24) to web-ports (80,443,8080) → Accept
	pkt1, err := config.PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())
	pkt2, err := config.PacketsFromBytes([]byte(testPackets2YAML))
	Expect(err).To(BeNil())
	pkt3, err := config.PacketsFromBytes([]byte(testPackets3YAML))
	Expect(err).To(BeNil())

	// First packet: src 192.168.1.5 dst 1.1.1.1:80 → matches rule 1 (Accept)
	m := &match.MatchContext{Packet: pkt1[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))

	// Second packet: src 10.0.0.1 dst 2.2.2.2:8080 → src is in trusted-ips (10.0.0.0/8),
	// dst port 8080 is in web-ports → matches rule 1 (Accept)
	m = &match.MatchContext{Packet: pkt2[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))

	// Third packet: src 172.16.0.1 → NOT in trusted-ips → falls through to deny-all (Drop)
	m = &match.MatchContext{Packet: pkt3[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Drop))
}

const testRulesWithNotSetsYAML = `
name: main
rules:
  - name: allow-non-blocked-src
    not_src:
      sets: [trusted-ips]
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`

func TestRulesReferencingNegatedNamedSets(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.Table().Rules)).To(Equal(2))
	Expect(engine.Table().Rules[0].NotSource.Sets).To(HaveLen(1))
}

func TestRulesWithNegatedNamedSetsMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).To(BeNil())

	pkt1, err := config.PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())
	pkt3, err := config.PacketsFromBytes([]byte(testPackets3YAML))
	Expect(err).To(BeNil())

	// First packet: src 192.168.1.5 — in trusted-ips → negated, rule1 does NOT match → deny-all (Drop)
	m := &match.MatchContext{Packet: pkt1[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Drop))

	// Third packet: src 172.16.0.1 — NOT in trusted-ips → rule1 matches (Accept)
	m = &match.MatchContext{Packet: pkt3[0]}
	engine.RunTest(m)
	Expect(m.Verdict).To(Equal(match.Accept))
}

func TestRulesReferencingUnknownNegatedSetError(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	// No sets loaded — negated set reference must fail at load time.
	err := loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
}

func TestLoadRulesFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	err := loadRulesFromBytes(engine, []byte(testRulesYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.Table().Rules)).To(Equal(3))

	// Verify first rule
	rule1 := engine.Table().Rules[0]
	Expect(rule1.Source.Net).ToNot(BeNil())
	Expect(rule1.Source.Net.String()).To(Equal("192.168.1.0/24"))
	Expect(rule1.Destination.Net).ToNot(BeNil())
	Expect(rule1.Destination.Net.String()).To(Equal("1.1.1.1/32"))
	Expect(rule1.Proto).ToNot(BeNil())
	Expect(rule1.Proto.Match(proto.Proto(7))).To(BeTrue())
	Expect(rule1.Action.String()).To(Equal("Accept"))

	// Verify second rule
	rule2 := engine.Table().Rules[1]
	Expect(rule2.Destination.Net).ToNot(BeNil())
	Expect(rule2.Destination.Net.String()).To(Equal("1.1.1.1/32"))
	Expect(rule2.Proto).ToNot(BeNil())
	Expect(rule2.Proto.Match(proto.Proto(7))).To(BeTrue())
	Expect(rule2.Action.String()).To(Equal("Drop"))

	// Verify default action is set
	Expect(engine.Table().DefaultAction.Action.String()).To(Equal("Accept"))
}
