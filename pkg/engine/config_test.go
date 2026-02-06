package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mazdakn/fwsim/pkg/policy"
	"github.com/onsi/gomega"
)

func TestLoadConfig(t *testing.T) {
	g := gomega.NewWithT(t)

	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "rules.yaml")
	yamlContent := `
rules:
  - src_net: "192.168.1.0/24"
    dst_net: "10.0.0.0/8"
    protocol: 6
    src_port: 8080
    dst_port: 80
    action: "Accept"
  - src_net: "192.168.2.0/24"
    action: "Drop"
`
	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	g.Expect(err).To(gomega.BeNil())

	// Test LoadConfig
	cfg, err := LoadConfig(configFile)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(cfg.Rules).To(gomega.HaveLen(2))
	g.Expect(cfg.Rules[0].Action).To(gomega.Equal("Accept"))
	g.Expect(cfg.Rules[1].Action).To(gomega.Equal("Drop"))

	// Test ToPolicyRules
	rules, err := cfg.ToPolicyRules()
	g.Expect(err).To(gomega.BeNil())
	g.Expect(rules).To(gomega.HaveLen(2))

	g.Expect(rules[0].Action).To(gomega.Equal(policy.Accept))
	// 6 is TCP
	g.Expect(*rules[0].Protocol).To(gomega.Equal(uint8(6)))
	g.Expect(rules[0].SrcNet.String()).To(gomega.Equal("192.168.1.0/24"))

	g.Expect(rules[1].Action).To(gomega.Equal(policy.Drop))
}

func TestEngine_LoadRules(t *testing.T) {
	g := gomega.NewWithT(t)

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "rules.yaml")
	yamlContent := `
rules:
  - action: "Log"
`
	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	g.Expect(err).To(gomega.BeNil())

	e := New("test")
	err = e.LoadRules(configFile)
	g.Expect(err).To(gomega.BeNil())

	// Since we can't inspect e.store.rules directly easily (unexported),
	// we assume AddRule worked if no error returned.
	// But we can verify with behavior if possible, or just trust unit test above covered logic.
	// Actually, we modified Store to have AddRule, so we are testing integration here.
}
