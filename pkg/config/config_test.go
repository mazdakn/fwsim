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
	Expect(os.MkdirAll(filepath.Join(dir, "rules"), 0o755)).To(Succeed())
	Expect(os.MkdirAll(filepath.Join(dir, "sets"), 0o755)).To(Succeed())
	Expect(os.MkdirAll(filepath.Join(dir, "packets"), 0o755)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "rules", "rules.yaml"), []byte(`
rules:
  - name: allow-http
    dst:
      port: [80]
    action: Accept
default_action: Drop
`), 0o600)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "sets", "sets.yaml"), []byte(`
sets:
  - name: web-ports
    type: port
    members: ["80", "443"]
`), 0o600)).To(Succeed())

	Expect(os.WriteFile(filepath.Join(dir, "packets", "packets.yaml"), []byte(`
packets:
  - src_addr: 10.0.0.1
    dst_addr: 1.1.1.1
    proto: 6
    src_port: 12345
    dst_port: 80
`), 0o600)).To(Succeed())

	resources, err := ConfigFromFile(Config{
		InputDir:    dir,
		PacketsFile: "enabled",
	})
	Expect(err).To(BeNil())
	Expect(resources.Table).ToNot(BeNil())
	Expect(resources.Sets).To(HaveLen(1))
	Expect(resources.Packets).To(HaveLen(1))
}

func TestConfigRulesFromDirConflictingDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	Expect(os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(`
rules: []
default_action: Accept
`), 0o600)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(`
rules: []
default_action: Drop
`), 0o600)).To(Succeed())

	tbl, err := ConfigRulesFromDir(dir, nil)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("conflicting default_action"))
	Expect(tbl).To(BeNil())
}

func TestConfigSetsFromDirMissingDirectory(t *testing.T) {
	RegisterTestingT(t)

	sets, err := ConfigSetsFromDir(filepath.Join(t.TempDir(), "sets"))
	Expect(err).To(BeNil())
	Expect(sets).To(Equal(map[string]set.Set{}))
}
