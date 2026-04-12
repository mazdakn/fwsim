package port

import (
	"fmt"
	"strconv"
	"strings"
)

// Port represents a network port, specified by number (e.g. 80) or name (e.g. "http").
// Number always holds the resolved port value. Name is set when the port was
// specified by name and is used for display purposes.
type Port struct {
	Number uint16
	Name   string
}

// wellKnownPorts maps common service names to their assigned port numbers.
var wellKnownPorts = map[string]uint16{
	"ftp":        21,
	"ssh":        22,
	"telnet":     23,
	"smtp":       25,
	"dns":        53,
	"http":       80,
	"pop3":       110,
	"imap":       143,
	"ldap":       389,
	"https":      443,
	"smb":        445,
	"mysql":      3306,
	"rdp":        3389,
	"postgresql": 5432,
	"redis":      6379,
	"mongodb":    27017,
}

// Parse parses a port from a string, accepting well-known service names (e.g.
// "http") or numeric values in the range 0–65535.
func Parse(s string) (*Port, error) {
	lower := strings.ToLower(s)
	if n, ok := wellKnownPorts[lower]; ok {
		return &Port{Number: n, Name: lower}, nil
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("unknown port: %s", s)
	}
	return &Port{Number: uint16(n)}, nil
}

// String returns the port name if the port was specified by name, otherwise its
// numeric value as a string.
func (p Port) String() string {
	if p.Name != "" {
		return p.Name
	}
	return strconv.Itoa(int(p.Number))
}

// UnmarshalYAML implements yaml.InterfaceUnmarshaler so that YAML values may be
// either a port name ("http", "https") or a numeric value (0–65535).
func (p *Port) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var n uint16
	if err := unmarshal(&n); err == nil {
		p.Number = n
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := Parse(s)
	if err != nil {
		return err
	}
	*p = *parsed
	return nil
}
