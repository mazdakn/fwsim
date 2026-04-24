package tests

// Integration / functional-verification tests for Engine.RunTests.
//
// Each test builds an Engine from Resources (tables, sets, intents), calls
// RunTests(), and asserts that every MatchContext carries the right verdict
// and/or matched rule.

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/config"
	enginepkg "github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/table"
	. "github.com/onsi/gomega"
)

// intentFromYAML is a test helper that parses an intent YAML string,
// failing the test on any error.
func intentFromYAML(t *testing.T, data string) *config.Intent {
	t.Helper()
	intent, err := config.IntentFromBytes([]byte(data))
	if err != nil {
		t.Fatalf("intentFromYAML: %v", err)
	}
	return intent
}

// TestRunTestsBasicAcceptAndDrop verifies that RunTests produces the correct
// verdict for each intent when a simple allow/deny table is loaded.
func TestRunTestsBasicAcceptAndDrop(t *testing.T) {
	RegisterTestingT(t)

	tbl, err := config.ConfigTableFromBytes([]byte(`
name: basic
rules:
  - name: allow-http
    dst:
      port: [80]
    proto: [6]
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	intents := []*config.Intent{
		intentFromYAML(t, `
name: http should be accepted
packet:
  src_addr: 10.0.0.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 12345
  dst_port: 80
expected_verdict: Accept
hit_by_rule: allow-http
`),
		intentFromYAML(t, `
name: ssh should be dropped
packet:
  src_addr: 10.0.0.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 12345
  dst_port: 22
expected_verdict: Drop
hit_by_rule: deny-all
`),
	}

	engine := enginepkg.New(&config.Resource{
		Tables:  []*table.Table{tbl},
		Intents: intents,
	})
	results := engine.RunTests()

	Expect(results).To(HaveLen(2))
	for _, m := range results {
		Expect(m.VerdictMatches()).To(BeTrue(), "intent %q: expected verdict %v, got %v", m.Packet.Metadata.Name, m.ExpectedVerdict, m.Verdict)
		Expect(m.RuleMatches()).To(BeTrue(), "intent %q: expected rule %q, last trace: %v", m.Packet.Metadata.Name, m.HitByRule, m.Trace)
	}
}

// TestRunTestsNoMatchReturnsNilVerdict verifies that a packet that passes
// through all tables without a definitive verdict results in a nil Verdict.
func TestRunTestsNoMatchReturnsNilVerdict(t *testing.T) {
	RegisterTestingT(t)

	// A table whose only rule passes HTTP, with a default Pass action — every
	// packet just flows through without a verdict.
	tbl, err := config.ConfigTableFromBytes([]byte(`
name: pass-all
rules:
  - name: pass-http
    dst:
      port: [80]
    proto: [6]
    action: Pass
default_action: Pass
`), nil)
	Expect(err).To(BeNil())

	intent := intentFromYAML(t, `
name: unmatched packet
packet:
  src_addr: 10.0.0.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 12345
  dst_port: 80
`)

	engine := enginepkg.New(&config.Resource{
		Tables:  []*table.Table{tbl},
		Intents: []*config.Intent{intent},
	})
	results := engine.RunTests()

	Expect(results).To(HaveLen(1))
	Expect(results[0].Verdict).To(BeNil())
}

// TestRunTestsWrongExpectedVerdictDetected ensures that VerdictMatches returns
// false when the intent specifies the wrong expected verdict.
func TestRunTestsWrongExpectedVerdictDetected(t *testing.T) {
	RegisterTestingT(t)

	tbl, err := config.ConfigTableFromBytes([]byte(`
name: strict-drop
rules: []
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	// The packet will be Dropped, but the intent expects Accept.
	intent := intentFromYAML(t, `
name: expecting wrong verdict
packet:
  src_addr: 10.0.0.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 12345
  dst_port: 80
expected_verdict: Accept
`)

	engine := enginepkg.New(&config.Resource{
		Tables:  []*table.Table{tbl},
		Intents: []*config.Intent{intent},
	})
	results := engine.RunTests()

	Expect(results).To(HaveLen(1))
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Drop)))
	Expect(results[0].VerdictMatches()).To(BeFalse())
}

// TestRunTestsWrongExpectedRuleDetected ensures that RuleMatches returns false
// when the intent names a rule that did NOT fire.
func TestRunTestsWrongExpectedRuleDetected(t *testing.T) {
	RegisterTestingT(t)

	tbl, err := config.ConfigTableFromBytes([]byte(`
name: simple
rules:
  - name: allow-http
    dst:
      port: [80]
    proto: [6]
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	// HTTP packet will hit allow-http, but the intent claims deny-all fired.
	intent := intentFromYAML(t, `
name: wrong expected rule
packet:
  src_addr: 10.0.0.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 12345
  dst_port: 80
expected_verdict: Accept
hit_by_rule: deny-all
`)

	engine := enginepkg.New(&config.Resource{
		Tables:  []*table.Table{tbl},
		Intents: []*config.Intent{intent},
	})
	results := engine.RunTests()

	Expect(results).To(HaveLen(1))
	Expect(results[0].VerdictMatches()).To(BeTrue())
	Expect(results[0].RuleMatches()).To(BeFalse())
}

// TestRunTestsWithNamedSets verifies end-to-end behavior when rules reference
// named sets and intents exercise packets that should match or not match those sets.
func TestRunTestsWithNamedSets(t *testing.T) {
	RegisterTestingT(t)

	sets, err := config.ConfigSetsFromBytes([]byte(`
name: trusted-nets
type: ip
members:
  - 192.168.0.0/16
  - 10.0.0.0/8
`))
	Expect(err).To(BeNil())

	webSets, err := config.ConfigSetsFromBytes([]byte(`
name: web-ports
type: port
members:
  - "80"
  - "443"
`))
	Expect(err).To(BeNil())

	for k, v := range webSets {
		sets[k] = v
	}

	tbl, err := config.ConfigTableFromBytes([]byte(`
name: set-rules
rules:
  - name: allow-trusted-web
    src:
      sets: [trusted-nets]
    dst:
      sets: [web-ports]
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`), sets)
	Expect(err).To(BeNil())

	intents := []*config.Intent{
		// Trusted source to web port → Accept
		intentFromYAML(t, `
name: trusted to http
packet:
  src_addr: 10.0.0.5
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 54321
  dst_port: 80
expected_verdict: Accept
hit_by_rule: allow-trusted-web
`),
		// Trusted source but non-web port → Drop
		intentFromYAML(t, `
name: trusted to ssh
packet:
  src_addr: 192.168.1.10
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 54321
  dst_port: 22
expected_verdict: Drop
hit_by_rule: deny-all
`),
		// Untrusted source to web port → Drop
		intentFromYAML(t, `
name: untrusted to https
packet:
  src_addr: 172.16.0.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 54321
  dst_port: 443
expected_verdict: Drop
hit_by_rule: deny-all
`),
	}

	engine := enginepkg.New(&config.Resource{
		Sets:    sets,
		Tables:  []*table.Table{tbl},
		Intents: intents,
	})
	results := engine.RunTests()

	Expect(results).To(HaveLen(3))
	for _, m := range results {
		Expect(m.VerdictMatches()).To(BeTrue(), "intent %q: expected %v got %v", m.Packet.Metadata.Name, m.ExpectedVerdict, m.Verdict)
		Expect(m.RuleMatches()).To(BeTrue(), "intent %q: expected rule %q", m.Packet.Metadata.Name, m.HitByRule)
	}
}

// TestRunTestsMultiTablePassContinuation verifies that when one table emits a
// Pass verdict, RunTests continues to the next table and the final verdict
// comes from that second table.
func TestRunTestsMultiTablePassContinuation(t *testing.T) {
	RegisterTestingT(t)

	filterTable, err := config.ConfigTableFromBytes([]byte(`
name: filter
order: 1
rules:
  - name: pass-internal
    src:
      net: [10.0.0.0/8]
    action: Pass
  - name: deny-external
    action: Drop
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	forwardTable, err := config.ConfigTableFromBytes([]byte(`
name: forward
order: 2
rules:
  - name: allow-http
    dst:
      port: [80]
    proto: [6]
    action: Accept
  - name: allow-https
    dst:
      port: [443]
    proto: [6]
    action: Accept
  - name: deny-rest
    action: Drop
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	intents := []*config.Intent{
		// Internal source to HTTP → passes filter, accepted in forward
		intentFromYAML(t, `
name: internal http
packet:
  src_addr: 10.0.0.5
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 54321
  dst_port: 80
expected_verdict: Accept
hit_by_rule: allow-http
`),
		// Internal source to HTTPS → passes filter, accepted in forward
		intentFromYAML(t, `
name: internal https
packet:
  src_addr: 10.1.2.3
  dst_addr: 2.2.2.2
  proto: 6
  src_port: 54321
  dst_port: 443
expected_verdict: Accept
hit_by_rule: allow-https
`),
		// Internal source to SSH → passes filter, dropped in forward
		intentFromYAML(t, `
name: internal ssh
packet:
  src_addr: 10.0.0.5
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 54321
  dst_port: 22
expected_verdict: Drop
hit_by_rule: deny-rest
`),
		// External source → dropped in filter, never reaches forward
		intentFromYAML(t, `
name: external blocked
packet:
  src_addr: 203.0.113.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 54321
  dst_port: 80
expected_verdict: Drop
hit_by_rule: deny-external
`),
	}

	engine := enginepkg.New(&config.Resource{
		Tables:  []*table.Table{filterTable, forwardTable},
		Intents: intents,
	})
	results := engine.RunTests()

	Expect(results).To(HaveLen(4))
	for _, m := range results {
		Expect(m.VerdictMatches()).To(BeTrue(), "intent %q: expected %v got %v", m.Packet.Metadata.Name, m.ExpectedVerdict, m.Verdict)
		Expect(m.RuleMatches()).To(BeTrue(), "intent %q: expected rule %q, trace: %v", m.Packet.Metadata.Name, m.HitByRule, m.Trace)
	}
}

// TestRunTestsVaryingIntentCounts verifies that RunTests correctly processes
// different numbers of match contexts passed directly as arguments.
func TestRunTestsVaryingIntentCounts(t *testing.T) {
	RegisterTestingT(t)

	tbl, err := config.ConfigTableFromBytes([]byte(`
name: main
rules:
  - name: allow-udp-dns
    dst:
      port: [53]
    proto: [17]
    action: Accept
  - name: deny-all
    action: Drop
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	firstIntent := intentFromYAML(t, `
name: dns query
packet:
  src_addr: 10.0.0.1
  dst_addr: 8.8.8.8
  proto: 17
  src_port: 54321
  dst_port: 53
expected_verdict: Accept
hit_by_rule: allow-udp-dns
`)

	// Run with a single intent.
	results := enginepkg.New(&config.Resource{
		Tables:  []*table.Table{tbl},
		Intents: []*config.Intent{firstIntent},
	}).RunTests()
	Expect(results).To(HaveLen(1))
	Expect(results[0].VerdictMatches()).To(BeTrue())
	Expect(results[0].RuleMatches()).To(BeTrue())

	secondIntent := intentFromYAML(t, `
name: blocked tcp
packet:
  src_addr: 10.0.0.1
  dst_addr: 8.8.8.8
  proto: 6
  src_port: 54321
  dst_port: 53
expected_verdict: Drop
hit_by_rule: deny-all
`)

	// Run with two intents using a fresh engine.
	results = enginepkg.New(&config.Resource{
		Tables:  []*table.Table{tbl},
		Intents: []*config.Intent{firstIntent, secondIntent},
	}).RunTests()
	Expect(results).To(HaveLen(2))
	for _, m := range results {
		Expect(m.VerdictMatches()).To(BeTrue())
		Expect(m.RuleMatches()).To(BeTrue())
	}
}

// TestRunTestsDefaultActionVerdict confirms that a packet reaching the end of
// a table without matching any explicit rule receives the table's default action.
func TestRunTestsDefaultActionVerdict(t *testing.T) {
	RegisterTestingT(t)

	tbl, err := config.ConfigTableFromBytes([]byte(`
name: accept-by-default
rules:
  - name: drop-udp
    proto: [17]
    action: Drop
default_action: Accept
`), nil)
	Expect(err).To(BeNil())

	intents := []*config.Intent{
		// UDP packet hits explicit rule → Drop
		intentFromYAML(t, `
name: udp traffic
packet:
  src_addr: 10.0.0.1
  dst_addr: 1.1.1.1
  proto: 17
  src_port: 12345
  dst_port: 53
expected_verdict: Drop
hit_by_rule: drop-udp
`),
		// TCP packet: no matching rule → falls to default Accept
		intentFromYAML(t, `
name: tcp traffic default accept
packet:
  src_addr: 10.0.0.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 12345
  dst_port: 8080
expected_verdict: Accept
`),
	}

	engine := enginepkg.New(&config.Resource{
		Tables:  []*table.Table{tbl},
		Intents: intents,
	})
	results := engine.RunTests()

	Expect(results).To(HaveLen(2))
	for _, m := range results {
		Expect(m.VerdictMatches()).To(BeTrue(), "intent %q: expected %v got %v", m.Packet.Metadata.Name, m.ExpectedVerdict, m.Verdict)
		Expect(m.RuleMatches()).To(BeTrue(), "intent %q: expected rule %q", m.Packet.Metadata.Name, m.HitByRule)
	}
}
