package engine

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
	. "github.com/onsi/gomega"
)

type testRuleConfig struct {
	Rules         []testRule `yaml:"rules,omitempty"`
	DefaultAction string     `yaml:"default_action,omitempty"`
}

type testEndpoint struct {
	Net       []string    `yaml:"net,omitempty"`
	Port      []port.Port `yaml:"port,omitempty"`
	IPSet     string      `yaml:"ip_set,omitempty"`
	PortSet   string      `yaml:"port_set,omitempty"`
	IPPortSet string      `yaml:"ipport_set,omitempty"`
}

func (e *testEndpoint) toEndpoint(ruleName string, sets map[string]set.Set) (rule.Endpoint, error) {
	var ep rule.Endpoint
	if len(e.Net) > 0 {
		ep.Net = set.NewIPSet()
		for _, n := range e.Net {
			if err := ep.Net.Add(rule.MustParseCIDR(n)); err != nil {
				return rule.Endpoint{}, err
			}
		}
	}
	if len(e.Port) > 0 {
		ep.Port = set.NewPortSet()
		for _, p := range e.Port {
			if err := ep.Port.Add(p); err != nil {
				return rule.Endpoint{}, err
			}
		}
	}
	if e.IPSet != "" {
		s, ok := sets[e.IPSet]
		if !ok {
			return ep, fmt.Errorf("rule %q references unknown set %q", ruleName, e.IPSet)
		}
		ep.IPSet = s
	}
	if e.PortSet != "" {
		s, ok := sets[e.PortSet]
		if !ok {
			return ep, fmt.Errorf("rule %q references unknown set %q", ruleName, e.PortSet)
		}
		ep.PortSet = s
	}
	if e.IPPortSet != "" {
		s, ok := sets[e.IPPortSet]
		if !ok {
			return ep, fmt.Errorf("rule %q references unknown set %q", ruleName, e.IPPortSet)
		}
		ep.IPPortSet = s
	}
	return ep, nil
}

type testRule struct {
	Name           string        `yaml:"name,omitempty"`
	Order          uint64        `yaml:"order,omitempty"`
	Source         testEndpoint  `yaml:"src,omitempty"`
	Destination    testEndpoint  `yaml:"dst,omitempty"`
	Protocol       []proto.Proto `yaml:"proto,omitempty"`
	NotSource      testEndpoint  `yaml:"not_src,omitempty"`
	NotDestination testEndpoint  `yaml:"not_dst,omitempty"`
	NotProto       []proto.Proto `yaml:"not_proto,omitempty"`
	Action         string        `yaml:"action,omitempty"`
}

func (r *testRule) toRule(sets map[string]set.Set) (*rule.Rule, error) {
	mRule := rule.New()
	mRule.Name = r.Name
	mRule.Order = r.Order
	mRule.Action = rule.MustParseAction(r.Action)

	if len(r.Protocol) > 0 {
		mRule.Proto = set.NewProtoSet()
		for _, p := range r.Protocol {
			if err := mRule.Proto.Add(p); err != nil {
				return nil, err
			}
		}
	}
	if len(r.NotProto) > 0 {
		mRule.NotProto = set.NewProtoSet()
		for _, p := range r.NotProto {
			if err := mRule.NotProto.Add(p); err != nil {
				return nil, err
			}
		}
	}

	var err error
	mRule.Source, err = r.Source.toEndpoint(r.Name, sets)
	if err != nil {
		return nil, err
	}
	mRule.Destination, err = r.Destination.toEndpoint(r.Name, sets)
	if err != nil {
		return nil, err
	}
	mRule.NotSource, err = r.NotSource.toEndpoint(r.Name, sets)
	if err != nil {
		return nil, err
	}
	mRule.NotDestination, err = r.NotDestination.toEndpoint(r.Name, sets)
	if err != nil {
		return nil, err
	}
	return mRule, nil
}

func rulesTableFromBytes(data []byte, sets map[string]set.Set) (*table.Table, error) {
	if sets == nil {
		sets = map[string]set.Set{}
	}
	var rc testRuleConfig
	if err := yaml.Unmarshal(data, &rc); err != nil {
		return nil, err
	}
	tbl := table.New("main", rule.MustParseAction(rc.DefaultAction))
	for _, r := range rc.Rules {
		mRule, err := r.toRule(sets)
		if err != nil {
			return nil, err
		}
		tbl.AddRule(mRule)
	}
	return tbl, nil
}

type testSetConfig struct {
	Sets []testSet `yaml:"sets,omitempty"`
}

type testSet struct {
	Name    string   `yaml:"name,omitempty"`
	Type    string   `yaml:"type,omitempty"`
	Members []string `yaml:"members,omitempty"`
}

func (s *testSet) toSet() (set.Set, error) {
	var result set.Set
	switch s.Type {
	case "ip":
		result = set.NewIPSet()
	case "port":
		result = set.NewPortSet()
	case "proto":
		result = set.NewProtoSet()
	case "ipport":
		result = set.NewIPPortSet()
	default:
		return nil, fmt.Errorf("unknown set type %q", s.Type)
	}
	for _, member := range s.Members {
		if err := result.Add(member); err != nil {
			return nil, fmt.Errorf("set %q: invalid member %q: %w", s.Name, member, err)
		}
	}
	return result, nil
}

func setsFromBytes(data []byte) (map[string]set.Set, error) {
	var sc testSetConfig
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return nil, err
	}
	sets := make(map[string]set.Set, len(sc.Sets))
	for _, s := range sc.Sets {
		namedSet, err := s.toSet()
		if err != nil {
			return nil, err
		}
		sets[s.Name] = namedSet
	}
	return sets, nil
}

type testPacketConfig struct {
	Packets []testPacket `yaml:"packets,omitempty"`
}

type testPacket struct {
	SrcAddr string      `yaml:"src_addr,omitempty"`
	DstAddr string      `yaml:"dst_addr,omitempty"`
	Proto   proto.Proto `yaml:"proto,omitempty"`
	SrcPort port.Port   `yaml:"src_port,omitempty"`
	DstPort port.Port   `yaml:"dst_port,omitempty"`

	Metadata packet.Metadata `yaml:"metadata,omitempty"`
}

func (p *testPacket) toPacket() *packet.Packet {
	return packet.New(
		packet.WithName(p.Metadata.Name),
		packet.WithSrcAddr(p.SrcAddr),
		packet.WithDstAddr(p.DstAddr),
		packet.WithProto(p.Proto),
		packet.WithSrcPort(p.SrcPort.Resolve()),
		packet.WithDstPort(p.DstPort.Resolve()),
	)
}

func packetsFromBytes(data []byte) ([]*packet.Packet, error) {
	var pc testPacketConfig
	if err := yaml.Unmarshal(data, &pc); err != nil {
		return nil, err
	}
	pkts := make([]*packet.Packet, 0, len(pc.Packets))
	for _, p := range pc.Packets {
		pkts = append(pkts, p.toPacket())
	}
	return pkts, nil
}

func loadRulesFromBytes(e *Engine, data []byte) error {
	tbl, err := rulesTableFromBytes(data, e.Sets())
	if err != nil {
		return err
	}
	e.SetTable(tbl)
	return nil
}

func loadSetsFromBytes(e *Engine, data []byte) error {
	sets, err := setsFromBytes(data)
	if err != nil {
		return err
	}
	e.SetSets(sets)
	return nil
}

const testRulesYAML = `
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

const testRulesNamedPortYAML = `
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
packets:
  - name: http to 1.1.1.1
    src_addr: 192.168.1.5
    dst_addr: 1.1.1.1
    proto: 6
    src_port: 30000
    dst_port: http
  - name: https to 2.2.2.2
    src_addr: 10.0.0.1
    dst_addr: 2.2.2.2
    proto: 6
    src_port: 12345
    dst_port: https
  - name: dns traffic
    src_addr: 172.16.0.1
    dst_addr: 8.8.8.8
    proto: 17
    src_port: 54321
    dst_port: dns
`

func TestEngineWithNamedPortsInRulesAndPackets(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	err := loadRulesFromBytes(engine, []byte(testRulesNamedPortYAML))
	Expect(err).To(BeNil())

	pkts, err := packetsFromBytes([]byte(testPacketsNamedPortYAML))
	Expect(err).To(BeNil())
	Expect(pkts).To(HaveLen(3))

	// Packet to port "http" (80) → matches allow-http rule (Accept)
	m := &match.Match{Packet: pkts[0]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))

	// Packet to port "https" (443) → matches allow-https rule (Accept)
	m = &match.Match{Packet: pkts[1]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))

	// Packet to port "dns" (53) with proto 17 → no matching rule → deny-all (Drop)
	m = &match.Match{Packet: pkts[2]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Drop))
}

const testSetsNamedPortYAML = `
sets:
  - name: named-web-ports
    type: port
    members:
      - http
      - https
      - ssh
`

func TestEngineWithNamedPortsInSets(t *testing.T) {
	RegisterTestingT(t)

	engine := New()

	err := loadSetsFromBytes(engine, []byte(testSetsNamedPortYAML))
	Expect(err).To(BeNil())

	const rulesWithNamedPortSetYAML = `
rules:
  - name: allow-named-web
    dst:
      port_set: named-web-ports
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`
	err = loadRulesFromBytes(engine, []byte(rulesWithNamedPortSetYAML))
	Expect(err).To(BeNil())

	pkts, err := packetsFromBytes([]byte(testPacketsNamedPortYAML))
	Expect(err).To(BeNil())

	// Packet to port "http" (80) → in named-web-ports → Accept
	m := &match.Match{Packet: pkts[0]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))

	// Packet to port "https" (443) → in named-web-ports → Accept
	m = &match.Match{Packet: pkts[1]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))

	// Packet to port "dns" (53) → NOT in named-web-ports → deny-all (Drop)
	m = &match.Match{Packet: pkts[2]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Drop))
}

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	Expect(engine).ToNot(BeNil())
}

func TestPacketsFromBytesAndMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	err := loadRulesFromBytes(engine, []byte(testRulesYAML))
	Expect(err).To(BeNil())

	pkts, err := packetsFromBytes([]byte(testPacketsYAML))
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

	engine := New()
	err := loadRulesFromBytes(engine, []byte(testRulesYAML))
	Expect(err).To(BeNil())

	err = loadSetsFromBytes(engine, []byte(testSetsYAML))
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
    src:
      ip_set: trusted-ips
    dst:
      port_set: web-ports
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`

func TestRulesReferencingNamedSets(t *testing.T) {
	RegisterTestingT(t)

	engine := New()

	// Sets must be loaded before rules that reference them.
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.Table().Rules)).To(Equal(2))

	rule1 := engine.Table().Rules[0]
	Expect(rule1.Source.IPSet).ToNot(BeNil())
	Expect(rule1.Destination.PortSet).ToNot(BeNil())
	Expect(rule1.Source.Net).To(BeNil())
	Expect(rule1.Destination.Port).To(BeNil())
}

func TestRulesReferencingUnknownSetError(t *testing.T) {
	RegisterTestingT(t)

	engine := New()

	// No sets loaded — referencing a set should return an error.
	err := loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
}

func TestRulesWithNamedSetsMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).To(BeNil())

	// Packet from trusted-ips (192.168.1.0/24) to web-ports (80,443,8080) → Accept
	pkts, err := packetsFromBytes([]byte(testPacketsYAML))
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

const testRulesWithNotSetsYAML = `
rules:
  - name: allow-non-blocked-src
    not_src:
      ip_set: trusted-ips
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`

func TestRulesReferencingNegatedNamedSets(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.Table().Rules)).To(Equal(2))
	Expect(engine.Table().Rules[0].NotSource.IPSet).ToNot(BeNil())
}

func TestRulesWithNegatedNamedSetsMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).To(BeNil())

	pkts, err := packetsFromBytes([]byte(testPacketsYAML))
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

	engine := New()
	// No sets loaded — negated set reference must fail at load time.
	err := loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
}

func TestLoadRulesFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := New()
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
