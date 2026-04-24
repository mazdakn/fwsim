package engine_test

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/config"
	enginepkg "github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	. "github.com/onsi/gomega"
)

func loadRulesFromBytes(e *enginepkg.Engine, data []byte) error {
	tbl, err := config.ConfigTableFromBytes(data, e.Sets())
	if err != nil {
		return err
	}
	e.RegisterTable(tbl)
	return nil
}

func loadSetsFromBytes(e *enginepkg.Engine, data []byte) error {
	sets, err := config.ConfigSetsFromBytes(data)
	if err != nil {
		return err
	}
	for name, s := range sets {
		e.RegisterSet(name, s)
	}
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

const testIntentYAML = `
name: access backend
packet:
  src_addr: 192.168.1.5
  dst_addr: 1.1.1.1
  proto: 7
  src_port: 30000
  dst_port: 80
`

const testIntent2YAML = `
name: access app1
packet:
  src_addr: 10.0.0.1
  dst_addr: 2.2.2.2
  proto: 7
  src_port: 12345
  dst_port: 8080
`

const testIntent3YAML = `
name: dns traffic
packet:
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

const testIntentNamedPortYAML = `
name: http to 1.1.1.1
packet:
  src_addr: 192.168.1.5
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 30000
  dst_port: http
`

const testIntentNamedPort2YAML = `
name: https to 2.2.2.2
packet:
  src_addr: 10.0.0.1
  dst_addr: 2.2.2.2
  proto: 6
  src_port: 12345
  dst_port: https
`

const testIntentNamedPort3YAML = `
name: dns traffic
packet:
  src_addr: 172.16.0.1
  dst_addr: 8.8.8.8
  proto: 17
  src_port: 54321
  dst_port: dns
`

func TestEngineWithNamedPortsInRulesAndPackets(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)
	err := loadRulesFromBytes(engine, []byte(testRulesNamedPortYAML))
	Expect(err).To(BeNil())

	intent1, err := config.IntentFromBytes([]byte(testIntentNamedPortYAML))
	Expect(err).To(BeNil())
	intent2, err := config.IntentFromBytes([]byte(testIntentNamedPort2YAML))
	Expect(err).To(BeNil())
	intent3, err := config.IntentFromBytes([]byte(testIntentNamedPort3YAML))
	Expect(err).To(BeNil())

	engine.RegisterIntent(intent1)
	engine.RegisterIntent(intent2)
	engine.RegisterIntent(intent3)
	results := engine.RunTests()

	// Packet to port "http" (80) → matches allow-http rule (Accept)
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	// Packet to port "https" (443) → matches allow-https rule (Accept)
	Expect(results[1].Verdict).To(HaveValue(Equal(rule.Accept)))
	// Packet to port "dns" (53) with proto 17 → no matching rule → deny-all (Drop)
	Expect(results[2].Verdict).To(HaveValue(Equal(rule.Drop)))
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

	engine := enginepkg.New(nil)

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

	pkt1, err := config.IntentFromBytes([]byte(testIntentNamedPortYAML))
	Expect(err).To(BeNil())
	pkt2, err := config.IntentFromBytes([]byte(testIntentNamedPort2YAML))
	Expect(err).To(BeNil())
	pkt3, err := config.IntentFromBytes([]byte(testIntentNamedPort3YAML))
	Expect(err).To(BeNil())

	engine.RegisterIntent(pkt1)
	engine.RegisterIntent(pkt2)
	engine.RegisterIntent(pkt3)
	results := engine.RunTests()

	// Packet to port "http" (80) → in named-web-ports → Accept
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	// Packet to port "https" (443) → in named-web-ports → Accept
	Expect(results[1].Verdict).To(HaveValue(Equal(rule.Accept)))
	// Packet to port "dns" (53) → NOT in named-web-ports → deny-all (Drop)
	Expect(results[2].Verdict).To(HaveValue(Equal(rule.Drop)))
}

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)
	Expect(engine).ToNot(BeNil())
}

func TestEnginePassRuleContinuesToNextTable(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)

	passTable, err := config.ConfigTableFromBytes([]byte(`
name: pass-table
order: 1
rules:
  - name: pass-http
    dst:
      port: [80]
    proto: [6]
    action: Pass
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	acceptTable, err := config.ConfigTableFromBytes([]byte(`
name: accept-table
order: 2
rules:
  - name: accept-http
    dst:
      port: [80]
    proto: [6]
    action: Accept
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	engine.RegisterTable(passTable)
	engine.RegisterTable(acceptTable)

	intent, err := config.IntentFromBytes([]byte(testIntentNamedPortYAML))
	Expect(err).To(BeNil())
	engine.RegisterIntent(intent)
	results := engine.RunTests()

	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(results[0].Trace).To(HaveLen(2))
	Expect(results[0].Trace[0].Name).To(Equal("pass-http"))
	Expect(results[0].Trace[1].Name).To(Equal("accept-http"))
}

func TestEnginePassDefaultActionContinuesToNextTable(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)

	passDefaultTable, err := config.ConfigTableFromBytes([]byte(`
name: pass-default
order: 1
rules: []
default_action: Pass
`), nil)
	Expect(err).To(BeNil())

	dropTable, err := config.ConfigTableFromBytes([]byte(`
name: drop-table
order: 2
rules:
  - name: drop-http
    dst:
      port: [80]
    proto: [6]
    action: Drop
default_action: Accept
`), nil)
	Expect(err).To(BeNil())

	engine.RegisterTable(passDefaultTable)
	engine.RegisterTable(dropTable)

	intent, err := config.IntentFromBytes([]byte(testIntentNamedPortYAML))
	Expect(err).To(BeNil())
	engine.RegisterIntent(intent)
	results := engine.RunTests()

	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Drop)))
	Expect(results[0].Trace).To(HaveLen(2))
	Expect(results[0].Trace[0].Name).To(Equal("table pass-default default action"))
	Expect(results[0].Trace[1].Name).To(Equal("drop-http"))
}

func TestEngineAllTablesPassResultsInNoMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)

	firstTable, err := config.ConfigTableFromBytes([]byte(`
name: first-pass
order: 1
rules: []
default_action: Pass
`), nil)
	Expect(err).To(BeNil())

	secondTable, err := config.ConfigTableFromBytes([]byte(`
name: second-pass
order: 2
rules:
  - name: pass-http
    dst:
      port: [80]
    proto: [6]
    action: Pass
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	engine.RegisterTable(firstTable)
	engine.RegisterTable(secondTable)

	intent, err := config.IntentFromBytes([]byte(testIntentNamedPortYAML))
	Expect(err).To(BeNil())
	engine.RegisterIntent(intent)
	results := engine.RunTests()

	Expect(results[0].Verdict).To(BeNil())
	Expect(results[0].Trace).To(HaveLen(2))
	Expect(results[0].Trace[0].Name).To(Equal("table first-pass default action"))
	Expect(results[0].Trace[1].Name).To(Equal("pass-http"))
}

func TestIntentsFromBytesAndMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)
	err := loadRulesFromBytes(engine, []byte(testRulesYAML))
	Expect(err).To(BeNil())

	intent1, err := config.IntentFromBytes([]byte(testIntentYAML))
	Expect(err).To(BeNil())
	intent2, err := config.IntentFromBytes([]byte(testIntent2YAML))
	Expect(err).To(BeNil())
	intent3, err := config.IntentFromBytes([]byte(testIntent3YAML))
	Expect(err).To(BeNil())

	engine.RegisterIntent(intent1)
	engine.RegisterIntent(intent2)
	engine.RegisterIntent(intent3)
	results := engine.RunTests()

	// First packet: src 192.168.1.5 -> dst 1.1.1.1:80 proto 7, src_port 30000 — matches rule 1 (Accept)
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	// Second packet: src 10.0.0.1 -> dst 2.2.2.2:8080 proto 7 — matches rule 3 (Drop)
	Expect(results[1].Verdict).To(HaveValue(Equal(rule.Drop)))
	// Third packet: proto 17, no matching rule — default action Accept
	Expect(results[2].Verdict).To(HaveValue(Equal(rule.Accept)))
}

func TestLoadSetsFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)
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

	engine := enginepkg.New(nil)

	// Sets must be loaded before rules that reference them.
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())
	err = loadSetsFromBytes(engine, []byte(testWebPortsSetYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.Tables()[0].Rules)).To(Equal(2))

	rule1 := engine.Tables()[0].Rules[0]
	Expect(rule1.Source.Sets).To(HaveLen(1))
	Expect(rule1.Destination.Sets).To(HaveLen(1))
	Expect(rule1.Source.Net).To(BeNil())
	Expect(rule1.Destination.Port).To(BeNil())
}

func TestRulesReferencingUnknownSetError(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)

	// No sets loaded — referencing a set should return an error.
	err := loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
}

func TestRulesWithNamedSetsMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())
	err = loadSetsFromBytes(engine, []byte(testWebPortsSetYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithSetsYAML))
	Expect(err).To(BeNil())

	// Packet from trusted-ips (192.168.1.0/24) to web-ports (80,443,8080) → Accept
	intent1, err := config.IntentFromBytes([]byte(testIntentYAML))
	Expect(err).To(BeNil())
	intent2, err := config.IntentFromBytes([]byte(testIntent2YAML))
	Expect(err).To(BeNil())
	intent3, err := config.IntentFromBytes([]byte(testIntent3YAML))
	Expect(err).To(BeNil())

	engine.RegisterIntent(intent1)
	engine.RegisterIntent(intent2)
	engine.RegisterIntent(intent3)
	results := engine.RunTests()

	// First packet: src 192.168.1.5 dst 1.1.1.1:80 → matches rule 1 (Accept)
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	// Second packet: src 10.0.0.1 dst 2.2.2.2:8080 → src is in trusted-ips (10.0.0.0/8),
	// dst port 8080 is in web-ports → matches rule 1 (Accept)
	Expect(results[1].Verdict).To(HaveValue(Equal(rule.Accept)))
	// Third packet: src 172.16.0.1 → NOT in trusted-ips → falls through to deny-all (Drop)
	Expect(results[2].Verdict).To(HaveValue(Equal(rule.Drop)))
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

	engine := enginepkg.New(nil)
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.Tables()[0].Rules)).To(Equal(2))
	Expect(engine.Tables()[0].Rules[0].NotSource.Sets).To(HaveLen(1))
}

func TestRulesWithNegatedNamedSetsMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)
	err := loadSetsFromBytes(engine, []byte(testSetsYAML))
	Expect(err).To(BeNil())

	err = loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).To(BeNil())

	intent1, err := config.IntentFromBytes([]byte(testIntentYAML))
	Expect(err).To(BeNil())
	intent3, err := config.IntentFromBytes([]byte(testIntent3YAML))
	Expect(err).To(BeNil())

	engine.RegisterIntent(intent1)
	engine.RegisterIntent(intent3)
	results := engine.RunTests()

	// First packet: src 192.168.1.5 — in trusted-ips → negated, rule1 does NOT match → deny-all (Drop)
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Drop)))
	// Third packet: src 172.16.0.1 — NOT in trusted-ips → rule1 matches (Accept)
	Expect(results[1].Verdict).To(HaveValue(Equal(rule.Accept)))
}

func TestRulesReferencingUnknownNegatedSetError(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)
	// No sets loaded — negated set reference must fail at load time.
	err := loadRulesFromBytes(engine, []byte(testRulesWithNotSetsYAML))
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("unknown set"))
}

func TestLoadRulesFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New(nil)
	err := loadRulesFromBytes(engine, []byte(testRulesYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.Tables()[0].Rules)).To(Equal(3))

	// Verify first rule
	rule1 := engine.Tables()[0].Rules[0]
	Expect(rule1.Source.Net).ToNot(BeNil())
	Expect(rule1.Source.Net.String()).To(Equal("192.168.1.0/24"))
	Expect(rule1.Destination.Net).ToNot(BeNil())
	Expect(rule1.Destination.Net.String()).To(Equal("1.1.1.1/32"))
	Expect(rule1.Proto).ToNot(BeNil())
	Expect(rule1.Proto.Match(proto.Proto(7))).To(BeTrue())
	Expect(rule1.Action.String()).To(Equal("Accept"))

	// Verify second rule
	rule2 := engine.Tables()[0].Rules[1]
	Expect(rule2.Destination.Net).ToNot(BeNil())
	Expect(rule2.Destination.Net.String()).To(Equal("1.1.1.1/32"))
	Expect(rule2.Proto).ToNot(BeNil())
	Expect(rule2.Proto.Match(proto.Proto(7))).To(BeTrue())
	Expect(rule2.Action.String()).To(Equal("Drop"))

	// Verify default action is set
	Expect(engine.Tables()[0].DefaultAction.Action.String()).To(Equal("Accept"))
}
