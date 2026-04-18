package config

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

func TestConfigFromDirLoadsAllResourceTypes(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()

	setsYAML := `
resources:
  - type: set
    name: trusted-ips
    spec:
      type: ip
      members:
        - 10.0.0.0/8
`
	rulesYAML := `
resources:
  - type: rule
    name: allow-trusted
    spec:
      src:
        ip_set: trusted-ips
      action: Accept
`
	packetsYAML := `
resources:
  - type: packet
    name: from-trusted
    spec:
      src_addr: 10.1.1.1
      dst_addr: 1.1.1.1
      proto: 6
      src_port: 12345
      dst_port: 80
`

	Expect(os.WriteFile(filepath.Join(dir, "sets.yaml"), []byte(setsYAML), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(rulesYAML), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(dir, "packets.yaml"), []byte(packetsYAML), 0o644)).To(Succeed())

	resources, err := ConfigFromDir(dir)
	Expect(err).To(BeNil())
	Expect(resources.Sets).To(HaveLen(1))
	Expect(resources.Sets).To(HaveKey("trusted-ips"))
	Expect(resources.Table).ToNot(BeNil())
	Expect(resources.Table.Rules).To(HaveLen(1))
	Expect(resources.Table.Rules[0].Name).To(Equal("allow-trusted"))
	Expect(resources.Packets).To(HaveLen(1))
	Expect(resources.Packets[0].Name).To(Equal("from-trusted"))
}

func TestConfigFromDirAcceptsSingleResourceFile(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	oneResourceYAML := `
type: set
name: web-ports
spec:
  type: port
  members:
    - "80"
    - "443"
`
	Expect(os.WriteFile(filepath.Join(dir, "single.yaml"), []byte(oneResourceYAML), 0o644)).To(Succeed())

	resources, err := ConfigFromDir(dir)
	Expect(err).To(BeNil())
	Expect(resources.Sets).To(HaveLen(1))
	Expect(resources.Sets).To(HaveKey("web-ports"))
}

func TestConfigFromDirRequiresTypeNameAndSpec(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	badYAML := `
resources:
  - name: missing-type
    spec:
      action: Accept
`
	Expect(os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(badYAML), 0o644)).To(Succeed())

	_, err := ConfigFromDir(dir)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("type is required"))
}
