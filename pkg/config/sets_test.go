package config

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestSetsFromFile(t *testing.T) {
	RegisterTestingT(t)

	sets, err := SetsFromFile("../../hack/sets.yaml")
	Expect(err).To(BeNil())
	Expect(sets).To(HaveLen(3))

	Expect(sets).To(HaveKey("trusted-ips"))
	Expect(sets).To(HaveKey("web-ports"))
	Expect(sets).To(HaveKey("allowed-protos"))
}

func TestSetsFromFileMissing(t *testing.T) {
	RegisterTestingT(t)

	sets, err := SetsFromFile("nonexistent.yaml")
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
