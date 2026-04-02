package proto

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
)

func TestProtoConstants(t *testing.T) {
	RegisterTestingT(t)

	Expect(ICMP).To(Equal(Proto(1)))
	Expect(TCP).To(Equal(Proto(6)))
	Expect(UDP).To(Equal(Proto(17)))
}

func TestProtoString(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		proto    Proto
		expected string
	}{
		{ICMP, "icmp"},
		{TCP, "tcp"},
		{UDP, "udp"},
		{Proto(0), "0"},
		{Proto(7), "7"},
		{Proto(255), "255"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			Expect(tt.proto.String()).To(Equal(tt.expected))
		})
	}
}

func TestProtoParse(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		input     string
		expected  Proto
		shouldErr bool
	}{
		{"tcp", TCP, false},
		{"TCP", TCP, false},
		{"udp", UDP, false},
		{"UDP", UDP, false},
		{"icmp", ICMP, false},
		{"ICMP", ICMP, false},
		{"6", TCP, false},
		{"17", UDP, false},
		{"1", ICMP, false},
		{"0", Proto(0), false},
		{"255", Proto(255), false},
		{"256", Proto(0), true},
		{"invalid", Proto(0), true},
		{"-1", Proto(0), true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p, err := Parse(tt.input)
			if tt.shouldErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(p).To(Equal(tt.expected))
			}
		})
	}
}

func TestProtoUnmarshalYAML(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name     string
		input    interface{}
		expected Proto
	}{
		{"numeric TCP", uint8(6), TCP},
		{"numeric UDP", uint8(17), UDP},
		{"numeric ICMP", uint8(1), ICMP},
		{"numeric zero", uint8(0), Proto(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Proto
			unmarshal := func(v interface{}) error {
				switch dst := v.(type) {
				case *uint8:
					*dst = tt.input.(uint8)
					return nil
				}
				return nil
			}
			Expect(p.UnmarshalYAML(unmarshal)).To(Succeed())
			Expect(p).To(Equal(tt.expected))
		})
	}
}

func TestProtoUnmarshalYAMLString(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name     string
		input    string
		expected Proto
	}{
		{"tcp string", "tcp", TCP},
		{"udp string", "udp", UDP},
		{"icmp string", "icmp", ICMP},
		{"numeric string", "7", Proto(7)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Proto
			unmarshal := func(v interface{}) error {
				switch dst := v.(type) {
				case *uint8:
					// force failure so string path is taken
					_ = dst
					return fmt.Errorf("not a uint8")
				case *string:
					*dst = tt.input
					return nil
				}
				return nil
			}
			Expect(p.UnmarshalYAML(unmarshal)).To(Succeed())
			Expect(p).To(Equal(tt.expected))
		})
	}
}
