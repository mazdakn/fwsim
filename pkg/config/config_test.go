package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mazdakn/fwsim/pkg/set"
	. "github.com/onsi/gomega"
)

func TestConfigFromDirectory(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	Expect(os.MkdirAll(filepath.Join(dir, "tables"), 0o755)).To(Succeed())
	Expect(os.MkdirAll(filepath.Join(dir, "sets"), 0o755)).To(Succeed())
	Expect(os.MkdirAll(filepath.Join(dir, "intents"), 0o755)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "tables", "tables.yaml"), []byte(`
name: main
rules:
  - name: allow-http
    dst:
      port: [80]
    action: Accept
default_action: Drop
`), 0o600)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "sets", "sets.yaml"), []byte(`
name: web-ports
type: port
members: ["80", "443"]
`), 0o600)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "intents", "intent.yaml"), []byte(`
name: http test
packet:
  src_addr: 10.0.0.1
  dst_addr: 1.1.1.1
  proto: 6
  src_port: 12345
  dst_port: 80
expected_verdict: Accept
hit_by_rule: allow-http
`), 0o600)).To(Succeed())

	e, intents, err := ConfigFromFile(Config{
		InputDir:    dir,
		LoadIntents: true,
	})
	Expect(err).To(BeNil())
	Expect(e.Tables).To(HaveLen(1))
	Expect(e.Sets).To(HaveLen(1))
	Expect(intents).To(HaveLen(1))
	Expect(e.Sets).To(HaveKey("web-ports"))
	Expect(e.Sets["web-ports"].Match(uint16(80))).To(BeTrue())
	Expect(e.Sets["web-ports"].Match(uint16(443))).To(BeTrue())
	Expect(intents[0].Packet.SrcAddr.String()).To(Equal("10.0.0.1"))
	Expect(intents[0].Packet.DstAddr.String()).To(Equal("1.1.1.1"))
	Expect(intents[0].Packet.SrcPort).To(Equal(uint16(12345)))
	Expect(intents[0].Packet.DstPort).To(Equal(uint16(80)))
}

func TestConfigTablesFromDirSortsByOrder(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	tablesDir := filepath.Join(dir, "tables")
	Expect(os.MkdirAll(tablesDir, 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(tablesDir, "a.yaml"), []byte(`
name: first
order: 10
rules: []
default_action: Accept
`), 0o600)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(tablesDir, "b.yaml"), []byte(`
name: second
order: 5
rules: []
default_action: Drop
`), 0o600)).To(Succeed())

	tables, err := ConfigTablesFromDir(tablesDir, nil)
	Expect(err).To(BeNil())
	Expect(tables).To(HaveLen(2))
	Expect(tables[0].Name).To(Equal("second"))
	Expect(tables[1].Name).To(Equal("first"))
}

func TestConfigTablesFromDirStableForEqualOrder(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	tablesDir := filepath.Join(dir, "tables")
	Expect(os.MkdirAll(tablesDir, 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(tablesDir, "a.yaml"), []byte(`
name: first
order: 10
rules: []
default_action: Accept
`), 0o600)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(tablesDir, "b.yaml"), []byte(`
name: second
order: 10
rules: []
default_action: Drop
`), 0o600)).To(Succeed())

	tables, err := ConfigTablesFromDir(tablesDir, nil)
	Expect(err).To(BeNil())
	Expect(tables).To(HaveLen(2))
	Expect(tables[0].Name).To(Equal("first"))
	Expect(tables[1].Name).To(Equal("second"))
}

func TestConfigSetsFromDirMissingDirectory(t *testing.T) {
	RegisterTestingT(t)

	sets, err := ConfigSetsFromDir(filepath.Join(t.TempDir(), "sets"))
	Expect(err).To(BeNil())
	Expect(sets).To(Equal(map[string]set.Set{}))
}

func TestConfigTablesFromDirMissingDirectory(t *testing.T) {
	RegisterTestingT(t)

	tables, err := ConfigTablesFromDir(filepath.Join(t.TempDir(), "tables"), nil)
	Expect(err).To(BeNil())
	Expect(tables).To(BeEmpty())
}

func TestConfigFromDirectoryWithoutIntentsWhenNotRequested(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	Expect(os.MkdirAll(filepath.Join(dir, "tables"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "tables", "tables.yaml"), []byte(`
name: main
rules: []
default_action: Accept
`), 0o600)).To(Succeed())

	e, _, err := ConfigFromFile(Config{
		InputDir: dir,
	})
	Expect(err).To(BeNil())
	Expect(e.Tables).To(HaveLen(1))
}

func TestConfigFromDirectoryWithoutTables(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	Expect(os.MkdirAll(filepath.Join(dir, "sets"), 0o755)).To(Succeed())

	e, _, err := ConfigFromFile(Config{
		InputDir: dir,
	})
	Expect(err).To(BeNil())
	Expect(e.Tables).To(BeEmpty())
}

func TestConfigFromFileWithoutInputDir(t *testing.T) {
	RegisterTestingT(t)

	e, _, err := ConfigFromFile(Config{})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("input directory is required"))
	Expect(e).To(BeNil())
}

func TestConfigSetsFromDirDuplicateNames(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	Expect(os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(`
name: dup-set
type: port
members: ["80"]
`), 0o600)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(`
name: dup-set
type: port
members: ["443"]
`), 0o600)).To(Succeed())

	sets, err := ConfigSetsFromDir(dir)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("duplicate set"))
	Expect(sets).To(BeNil())
}
