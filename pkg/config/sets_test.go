package config

import (
	"testing"

	. "github.com/onsi/gomega"
)

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
  - name: service-tuples
    type: ipport
    members:
      - "1.1.1.1,tcp,443"
      - "10.0.0.0/8,udp,53"
`

func TestSetsFromBytes(t *testing.T) {
	RegisterTestingT(t)

	sets, err := SetsFromBytes([]byte(testSetsYAML))
	Expect(err).To(BeNil())
	Expect(sets).To(HaveLen(4))

	Expect(sets).To(HaveKey("trusted-ips"))
	Expect(sets).To(HaveKey("web-ports"))
	Expect(sets).To(HaveKey("allowed-protos"))
	Expect(sets).To(HaveKey("service-tuples"))
}

func TestSetsFromBytesInvalid(t *testing.T) {
	RegisterTestingT(t)

	sets, err := SetsFromBytes([]byte("not: valid: yaml: ["))
	Expect(err).ToNot(BeNil())
	Expect(sets).To(BeNil())
}

func TestSetToSetIP(t *testing.T) {
	RegisterTestingT(t)

	s := &Set{
		Name:    "my-ips",
		Type:    "ip",
		Members: []string{"10.0.0.0/8", "192.168.0.0/16"},
	}
	result, err := s.ToSet()
	Expect(err).To(BeNil())
	Expect(result).ToNot(BeNil())
}

func TestSetToSetPort(t *testing.T) {
	RegisterTestingT(t)

	s := &Set{
		Name:    "my-ports",
		Type:    "port",
		Members: []string{"80", "443"},
	}
	result, err := s.ToSet()
	Expect(err).To(BeNil())
	Expect(result).ToNot(BeNil())
}

func TestSetToSetPortNamed(t *testing.T) {
	RegisterTestingT(t)

	s := &Set{
		Name:    "my-named-ports",
		Type:    "port",
		Members: []string{"http", "https"},
	}
	result, err := s.ToSet()
	Expect(err).To(BeNil())
	Expect(result).ToNot(BeNil())
	Expect(result.Match(uint16(80))).To(BeTrue())
	Expect(result.Match(uint16(443))).To(BeTrue())
	Expect(result.Match(uint16(8080))).To(BeFalse())
}

func TestSetToSetProto(t *testing.T) {
	RegisterTestingT(t)

	s := &Set{
		Name:    "my-protos",
		Type:    "proto",
		Members: []string{"tcp", "udp"},
	}
	result, err := s.ToSet()
	Expect(err).To(BeNil())
	Expect(result).ToNot(BeNil())
}

func TestSetToSetIPPort(t *testing.T) {
	RegisterTestingT(t)

	s := &Set{
		Name:    "my-ipports",
		Type:    "ipport",
		Members: []string{"10.0.0.0/8,tcp,80", "1.1.1.1,udp,53"},
	}
	result, err := s.ToSet()
	Expect(err).To(BeNil())
	Expect(result).ToNot(BeNil())
}

func TestSetToSetUnknownType(t *testing.T) {
	RegisterTestingT(t)

	s := &Set{
		Name:    "bad-set",
		Type:    "unknown",
		Members: []string{"foo"},
	}
	result, err := s.ToSet()
	Expect(err).ToNot(BeNil())
	Expect(result).To(BeNil())
}

func TestSetToSetInvalidMember(t *testing.T) {
	RegisterTestingT(t)

	s := &Set{
		Name:    "bad-ips",
		Type:    "ip",
		Members: []string{"not-a-cidr"},
	}
	result, err := s.ToSet()
	Expect(err).ToNot(BeNil())
	Expect(result).To(BeNil())
}
