package port

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"
)

func TestPortConstants(t *testing.T) {
	RegisterTestingT(t)

	Expect(wellKnownPorts["http"]).To(Equal(uint16(80)))
	Expect(wellKnownPorts["https"]).To(Equal(uint16(443)))
	Expect(wellKnownPorts["ssh"]).To(Equal(uint16(22)))
	Expect(wellKnownPorts["dns"]).To(Equal(uint16(53)))
}

func TestPortString(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		port     Port
		expected string
	}{
		{Port{Number: 80, Name: "http"}, "http"},
		{Port{Number: 443, Name: "https"}, "https"},
		{Port{Number: 80}, "80"},
		{Port{Number: 0}, "0"},
		{Port{Number: 65535}, "65535"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			Expect(tt.port.String()).To(Equal(tt.expected))
		})
	}
}

func TestPortParse(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		input     string
		expected  *Port
		shouldErr bool
	}{
		{"http", &Port{Number: 80, Name: "http"}, false},
		{"HTTP", &Port{Number: 80, Name: "http"}, false},
		{"https", &Port{Number: 443, Name: "https"}, false},
		{"ssh", &Port{Number: 22, Name: "ssh"}, false},
		{"dns", &Port{Number: 53, Name: "dns"}, false},
		{"ftp", &Port{Number: 21, Name: "ftp"}, false},
		{"smtp", &Port{Number: 25, Name: "smtp"}, false},
		{"80", &Port{Number: 80}, false},
		{"443", &Port{Number: 443}, false},
		{"0", &Port{Number: 0}, false},
		{"65535", &Port{Number: 65535}, false},
		{"65536", nil, true},
		{"invalid", nil, true},
		{"-1", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p, err := Parse(tt.input)
			if tt.shouldErr {
				Expect(err).To(HaveOccurred())
				Expect(p).To(BeNil())
			} else {
				Expect(err).ToNot(HaveOccurred())
				Expect(p).ToNot(BeNil())
				Expect(*p).To(Equal(*tt.expected))
			}
		})
	}
}

func TestPortUnmarshalYAML(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name     string
		input    interface{}
		expected Port
	}{
		{"numeric 80", uint16(80), Port{Number: 80}},
		{"numeric 443", uint16(443), Port{Number: 443}},
		{"numeric 0", uint16(0), Port{Number: 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Port
			unmarshal := func(v interface{}) error {
				switch dst := v.(type) {
				case *uint16:
					*dst = tt.input.(uint16)
					return nil
				}
				return fmt.Errorf("unexpected type")
			}
			Expect(p.UnmarshalYAML(unmarshal)).To(Succeed())
			Expect(p).To(Equal(tt.expected))
		})
	}
}

func TestPortUnmarshalYAMLString(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name     string
		input    string
		expected Port
	}{
		{"http string", "http", Port{Number: 80, Name: "http"}},
		{"https string", "https", Port{Number: 443, Name: "https"}},
		{"ssh string", "ssh", Port{Number: 22, Name: "ssh"}},
		{"numeric string 80", "80", Port{Number: 80}},
		{"numeric string 443", "443", Port{Number: 443}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Port
			unmarshal := func(v interface{}) error {
				switch dst := v.(type) {
				case *uint16:
					_ = dst
					return fmt.Errorf("not a uint16")
				case *string:
					*dst = tt.input
					return nil
				}
				return fmt.Errorf("unexpected type")
			}
			Expect(p.UnmarshalYAML(unmarshal)).To(Succeed())
			Expect(p).To(Equal(tt.expected))
		})
	}
}

func TestPortUnmarshalYAMLInvalidName(t *testing.T) {
	RegisterTestingT(t)

	var p Port
	unmarshal := func(v interface{}) error {
		switch dst := v.(type) {
		case *uint16:
			_ = dst
			return fmt.Errorf("not a uint16")
		case *string:
			*dst = "notaport"
			return nil
		}
		return fmt.Errorf("unexpected type")
	}
	Expect(p.UnmarshalYAML(unmarshal)).To(HaveOccurred())
}
