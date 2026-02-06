package config

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
)

func TestParseConfig_ValidYAML(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(`
Policies:
  - match:
    - src: 192.168.1.0/24:*
      dst: 1.1.1.1:80
      proto: tcp
    action: accept
  - match:
    - dst: 1.1.1.1:80
      proto: 80
    action: Drop
traffic:
  - src: 192.168.10.1:*
    dst: 1.1.1.1:80
    proto: tcp
    result: Accept
  - src: "*"
    dst: 2.2.2.2:*
    proto: udp
    result: Reject
`)

	config, err := ParseConfig(yamlData)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())

	// Verify policies
	Expect(config.Policies).To(HaveLen(2))
	
	// First policy
	Expect(config.Policies[0].Match).To(HaveLen(1))
	Expect(config.Policies[0].Match[0].Src).To(Equal("192.168.1.0/24:*"))
	Expect(config.Policies[0].Match[0].Dst).To(Equal("1.1.1.1:80"))
	Expect(config.Policies[0].Match[0].Proto).To(Equal("tcp"))
	Expect(config.Policies[0].Action).To(Equal("accept"))

	// Second policy
	Expect(config.Policies[1].Match).To(HaveLen(1))
	Expect(config.Policies[1].Match[0].Src).To(BeEmpty())
	Expect(config.Policies[1].Match[0].Dst).To(Equal("1.1.1.1:80"))
	Expect(config.Policies[1].Match[0].Proto).To(Equal("80"))
	Expect(config.Policies[1].Action).To(Equal("Drop"))

	// Verify traffic
	Expect(config.Traffic).To(HaveLen(2))
	
	// First traffic rule
	Expect(config.Traffic[0].Src).To(Equal("192.168.10.1:*"))
	Expect(config.Traffic[0].Dst).To(Equal("1.1.1.1:80"))
	Expect(config.Traffic[0].Proto).To(Equal("tcp"))
	Expect(config.Traffic[0].Result).To(Equal("Accept"))

	// Second traffic rule
	Expect(config.Traffic[1].Src).To(Equal("*"))
	Expect(config.Traffic[1].Dst).To(Equal("2.2.2.2:*"))
	Expect(config.Traffic[1].Proto).To(Equal("udp"))
	Expect(config.Traffic[1].Result).To(Equal("Reject"))
}

func TestParseConfig_EmptyYAML(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(``)

	config, err := ParseConfig(yamlData)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	Expect(config.Policies).To(BeEmpty())
	Expect(config.Traffic).To(BeEmpty())
}

func TestParseConfig_OnlyPolicies(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(`
Policies:
  - match:
    - src: 10.0.0.0/8:*
      dst: "*"
      proto: tcp
    action: accept
`)

	config, err := ParseConfig(yamlData)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	Expect(config.Policies).To(HaveLen(1))
	Expect(config.Traffic).To(BeEmpty())
}

func TestParseConfig_OnlyTraffic(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(`
traffic:
  - src: 10.0.0.1:12345
    dst: 8.8.8.8:53
    proto: udp
    result: Accept
`)

	config, err := ParseConfig(yamlData)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	Expect(config.Policies).To(BeEmpty())
	Expect(config.Traffic).To(HaveLen(1))
	Expect(config.Traffic[0].Src).To(Equal("10.0.0.1:12345"))
	Expect(config.Traffic[0].Dst).To(Equal("8.8.8.8:53"))
	Expect(config.Traffic[0].Proto).To(Equal("udp"))
	Expect(config.Traffic[0].Result).To(Equal("Accept"))
}

func TestParseConfig_InvalidYAML(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(`
invalid yaml content:
  this is not: [valid
`)

	config, err := ParseConfig(yamlData)
	Expect(err).To(HaveOccurred())
	Expect(config).To(BeNil())
}

func TestParseConfig_MultipleMatchCriteria(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(`
Policies:
  - match:
    - src: 10.0.0.0/8:*
      dst: 1.1.1.1:80
      proto: tcp
    - src: 172.16.0.0/12:*
      dst: 1.1.1.1:443
      proto: tcp
    action: accept
`)

	config, err := ParseConfig(yamlData)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	Expect(config.Policies).To(HaveLen(1))
	Expect(config.Policies[0].Match).To(HaveLen(2))
	
	// First match
	Expect(config.Policies[0].Match[0].Src).To(Equal("10.0.0.0/8:*"))
	Expect(config.Policies[0].Match[0].Dst).To(Equal("1.1.1.1:80"))
	Expect(config.Policies[0].Match[0].Proto).To(Equal("tcp"))
	
	// Second match
	Expect(config.Policies[0].Match[1].Src).To(Equal("172.16.0.0/12:*"))
	Expect(config.Policies[0].Match[1].Dst).To(Equal("1.1.1.1:443"))
	Expect(config.Policies[0].Match[1].Proto).To(Equal("tcp"))
}

func TestParseConfig_PartialMatchCriteria(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(`
Policies:
  - match:
    - dst: 1.1.1.1:80
    action: drop
  - match:
    - proto: udp
    action: reject
`)

	config, err := ParseConfig(yamlData)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	Expect(config.Policies).To(HaveLen(2))
	
	// First policy - only dst specified
	Expect(config.Policies[0].Match[0].Src).To(BeEmpty())
	Expect(config.Policies[0].Match[0].Dst).To(Equal("1.1.1.1:80"))
	Expect(config.Policies[0].Match[0].Proto).To(BeEmpty())
	Expect(config.Policies[0].Action).To(Equal("drop"))
	
	// Second policy - only proto specified
	Expect(config.Policies[1].Match[0].Src).To(BeEmpty())
	Expect(config.Policies[1].Match[0].Dst).To(BeEmpty())
	Expect(config.Policies[1].Match[0].Proto).To(Equal("udp"))
	Expect(config.Policies[1].Action).To(Equal("reject"))
}

func TestLoadConfig_ValidFile(t *testing.T) {
	RegisterTestingT(t)

	// Create a temporary file with valid YAML
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test-config.yaml")

	yamlContent := []byte(`
Policies:
  - match:
    - src: 192.168.1.0/24:*
      dst: 1.1.1.1:80
      proto: tcp
    action: accept
traffic:
  - src: 192.168.10.1:*
    dst: 1.1.1.1:80
    proto: tcp
    result: Accept
`)

	err := os.WriteFile(tmpFile, yamlContent, 0644)
	Expect(err).ToNot(HaveOccurred())

	// Load the config
	config, err := LoadConfig(tmpFile)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	Expect(config.Policies).To(HaveLen(1))
	Expect(config.Traffic).To(HaveLen(1))
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	RegisterTestingT(t)

	config, err := LoadConfig("/nonexistent/path/config.yaml")
	Expect(err).To(HaveOccurred())
	Expect(config).To(BeNil())
}

func TestLoadConfig_InvalidYAMLInFile(t *testing.T) {
	RegisterTestingT(t)

	// Create a temporary file with invalid YAML
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid-config.yaml")

	invalidContent := []byte(`this is: [invalid yaml`)
	err := os.WriteFile(tmpFile, invalidContent, 0644)
	Expect(err).ToNot(HaveOccurred())

	// Try to load the config
	config, err := LoadConfig(tmpFile)
	Expect(err).To(HaveOccurred())
	Expect(config).To(BeNil())
}

func TestLoadConfig_WithSimpleYAML(t *testing.T) {
	RegisterTestingT(t)

	// Test with the actual simple.yaml file if it exists
	simpleYAMLPath := "../../hack/simple.yaml"
	if _, err := os.Stat(simpleYAMLPath); os.IsNotExist(err) {
		t.Skip("simple.yaml not found, skipping test")
		return
	}

	config, err := LoadConfig(simpleYAMLPath)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	
	// Verify basic structure based on simple.yaml content
	Expect(config.Policies).ToNot(BeEmpty())
	Expect(config.Traffic).ToNot(BeEmpty())
}

func TestParseConfig_NumericProtocol(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(`
Policies:
  - match:
    - proto: "80"
    action: accept
traffic:
  - src: "*"
    dst: 1.1.1.1:80
    proto: "6"
    result: Accept
`)

	config, err := ParseConfig(yamlData)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	Expect(config.Policies[0].Match[0].Proto).To(Equal("80"))
	Expect(config.Traffic[0].Proto).To(Equal("6"))
}

func TestParseConfig_IPv6Addresses(t *testing.T) {
	RegisterTestingT(t)

	yamlData := []byte(`
Policies:
  - match:
    - src: 2001:db8::/32:*
      dst: 2001:db8::1:80
      proto: tcp
    action: accept
traffic:
  - src: 2001:db8::1:12345
    dst: 2001:db8::2:80
    proto: tcp
    result: Accept
`)

	config, err := ParseConfig(yamlData)
	Expect(err).ToNot(HaveOccurred())
	Expect(config).ToNot(BeNil())
	Expect(config.Policies).To(HaveLen(1))
	Expect(config.Policies[0].Match[0].Src).To(Equal("2001:db8::/32:*"))
	Expect(config.Policies[0].Match[0].Dst).To(Equal("2001:db8::1:80"))
	Expect(config.Traffic[0].Src).To(Equal("2001:db8::1:12345"))
	Expect(config.Traffic[0].Dst).To(Equal("2001:db8::2:80"))
}
