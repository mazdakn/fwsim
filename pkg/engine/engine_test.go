package engine_test

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/config"
	enginepkg "github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/rule"
	"github.com/mazdakn/fwsim/pkg/table"
	. "github.com/onsi/gomega"
)

func mustTableFromYAML(t *testing.T, data string) *table.Table {
	t.Helper()
	tbl, err := config.ConfigTableFromBytes([]byte(data), nil)
	if err != nil {
		t.Fatalf("failed to build table from yaml: %v", err)
	}
	return tbl
}

func mustPacket(t *testing.T) *match.Match {
	t.Helper()
	pkts, err := config.PacketsFromBytes([]byte(`
src_addr: 10.0.0.1
dst_addr: 1.1.1.1
proto: 6
src_port: 12345
dst_port: 80
`))
	if err != nil {
		t.Fatalf("failed to parse packet: %v", err)
	}
	return &match.Match{Packet: pkts[0]}
}

func TestRunTestPassesBetweenTables(t *testing.T) {
	RegisterTestingT(t)

	first := mustTableFromYAML(t, `
name: first
order: 1
default_action: Pass
rules: []
`)
	second := mustTableFromYAML(t, `
name: second
order: 2
default_action: Drop
rules:
  - name: allow-http
    dst:
      port: [80]
    proto: [6]
    action: Accept
`)

	engine := enginepkg.New(enginepkg.Resources{Tables: []*table.Table{first, second}})
	m := mustPacket(t)
	engine.RunTest(m)

	Expect(m.Result.Verdict).To(Equal(rule.Accept))
	Expect(m.Result.Trace).To(HaveLen(2))
}

func TestRunTestWithoutTablesReturnsPass(t *testing.T) {
	RegisterTestingT(t)

	engine := enginepkg.New()
	m := mustPacket(t)
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Pass))
}

func TestValidateAllRulesUsedAcrossTables(t *testing.T) {
	RegisterTestingT(t)

	first := mustTableFromYAML(t, `
name: first
order: 1
default_action: Pass
rules:
  - name: unused-rule
    action: Drop
`)

	engine := enginepkg.New(enginepkg.Resources{Tables: []*table.Table{first}})
	Expect(engine.Validate()).To(ContainElement("Table 0 Rule 0 not used"))
}
