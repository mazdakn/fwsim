package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mazdakn/fwsim/pkg/engine"
	"github.com/mazdakn/fwsim/pkg/set"
	. "github.com/onsi/gomega"
)

func TestConfigFromDirectory(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	Expect(os.MkdirAll(filepath.Join(dir, "tables"), 0o755)).To(Succeed())
	Expect(os.MkdirAll(filepath.Join(dir, "sets"), 0o755)).To(Succeed())
	Expect(os.MkdirAll(filepath.Join(dir, "packets"), 0o755)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "tables", "main.yaml"), []byte(`
name: main
order: 20
default_action: Drop
rules:
  - name: allow-http
    dst:
      port: [80]
    action: Accept
`), 0o600)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "tables", "before-main.yaml"), []byte(`
name: before-main
order: 10
default_action: Pass
rules: []
`), 0o600)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "sets", "sets.yaml"), []byte(`
name: web-ports
type: port
members: ["80", "443"]
`), 0o600)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "packets", "packets.yaml"), []byte(`
src_addr: 10.0.0.1
dst_addr: 1.1.1.1
proto: 6
src_port: 12345
dst_port: 80
`), 0o600)).To(Succeed())

	resources, err := ConfigFromFile(Config{
		InputDir:    dir,
		LoadPackets: true,
	})
	Expect(err).To(BeNil())
	Expect(resources.Tables).To(HaveLen(2))
	Expect(resources.Tables[0].Name).To(Equal("before-main"))
	Expect(resources.Tables[1].Name).To(Equal("main"))
	Expect(resources.Sets).To(HaveLen(1))
	Expect(resources.Packets).To(HaveLen(1))
	Expect(resources.Sets).To(HaveKey("web-ports"))
	Expect(resources.Sets["web-ports"].Match(uint16(80))).To(BeTrue())
	Expect(resources.Packets[0].SrcAddr.String()).To(Equal("10.0.0.1"))
	Expect(resources.Packets[0].DstPort).To(Equal(uint16(80)))
}

func TestConfigFromDirectoryWithoutTables(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	resources, err := ConfigFromFile(Config{InputDir: dir})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("failed to read tables directory"))
	Expect(resources).To(Equal(engine.Resources{}))
}

func TestConfigSetsFromDirMissingDirectory(t *testing.T) {
	RegisterTestingT(t)

	sets, err := ConfigSetsFromDir(filepath.Join(t.TempDir(), "sets"))
	Expect(err).To(BeNil())
	Expect(sets).To(Equal(map[string]set.Set{}))
}

func TestConfigFromDirectoryWithoutPacketsWhenNotRequested(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	Expect(os.MkdirAll(filepath.Join(dir, "tables"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "tables", "table.yaml"), []byte(`
name: main
order: 0
default_action: Accept
rules: []
`), 0o600)).To(Succeed())

	resources, err := ConfigFromFile(Config{
		InputDir: dir,
	})
	Expect(err).To(BeNil())
	Expect(resources.Tables).To(HaveLen(1))
	Expect(resources.Packets).To(BeNil())
}

func TestConfigFromFileWithoutInputDir(t *testing.T) {
	RegisterTestingT(t)

	resources, err := ConfigFromFile(Config{})
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("input directory is required"))
	Expect(resources).To(Equal(engine.Resources{}))
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

func TestConfigTablesFromDirSortedAscending(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	Expect(os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(`
name: table-b
order: 2
default_action: Drop
rules: []
`), 0o600)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(`
name: table-a
order: 1
default_action: Accept
rules: []
`), 0o600)).To(Succeed())

	tables, err := ConfigTablesFromDir(dir, nil)
	Expect(err).To(BeNil())
	Expect(tables).To(HaveLen(2))
	Expect(tables[0].Name).To(Equal("table-a"))
	Expect(tables[1].Name).To(Equal("table-b"))
}
