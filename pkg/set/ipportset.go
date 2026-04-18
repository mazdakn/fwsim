package set

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/mazdakn/fwsim/pkg/port"
	"github.com/mazdakn/fwsim/pkg/proto"
)

// IPPortTuple is a runtime value used to test membership in an IPPortSet.
type IPPortTuple struct {
	IP    net.IP
	Proto proto.Proto
	Port  uint16
}

type ipPortMember struct {
	net   *net.IPNet
	proto proto.Proto
	start uint16
	end   uint16
}

func (m ipPortMember) String() string {
	portExpr := strconv.Itoa(int(m.start))
	if m.end > m.start {
		portExpr = fmt.Sprintf("%d-%d", m.start, m.end)
	}
	return fmt.Sprintf("%s,%s,%s", m.net.String(), m.proto.String(), portExpr)
}

// IPPortSet matches an IP, protocol, and port tuple.
type IPPortSet struct {
	members []ipPortMember
}

// NewIPPortSet returns an empty IPPortSet.
func NewIPPortSet() *IPPortSet {
	return &IPPortSet{
		members: nil,
	}
}

// Add inserts a value into the set.
// v must be a string in the form "ip-or-cidr,proto,port-or-range".
func (s *IPPortSet) Add(v any) error {
	switch val := v.(type) {
	case string:
		member, err := parseIPPortMember(val)
		if err != nil {
			return err
		}
		s.members = append(s.members, member)
		return nil
	default:
		return fmt.Errorf("IPPortSet.Add: unsupported type %T", v)
	}
}

// Match reports whether v is contained in the set.
// v must be an IPPortTuple value.
func (s *IPPortSet) Match(v any) bool {
	tuple, ok := v.(IPPortTuple)
	if !ok {
		return false
	}
	for _, member := range s.members {
		if !member.net.Contains(tuple.IP) {
			continue
		}
		if member.proto != tuple.Proto {
			continue
		}
		if tuple.Port < member.start || tuple.Port > member.end {
			continue
		}
		return true
	}
	return false
}

// String returns a human-readable representation of the IPPortSet.
func (s *IPPortSet) String() string {
	if len(s.members) == 0 {
		return "{}"
	}
	memberStrings := make([]string, 0, len(s.members))
	for _, member := range s.members {
		memberStrings = append(memberStrings, member.String())
	}
	sort.Strings(memberStrings)
	if len(memberStrings) == 1 {
		return memberStrings[0]
	}
	return "{" + strings.Join(memberStrings, ",") + "}"
}

func parseIPPortMember(v string) (ipPortMember, error) {
	parts := strings.Split(v, ",")
	if len(parts) != 3 {
		return ipPortMember{}, fmt.Errorf("invalid ipport member %q: expected format ip-or-cidr,proto,port", v)
	}
	ipExpr := strings.TrimSpace(parts[0])
	protoExpr := strings.TrimSpace(parts[1])
	portExpr := strings.TrimSpace(parts[2])

	ipnet, err := parseIPOrCIDR(ipExpr)
	if err != nil {
		return ipPortMember{}, fmt.Errorf("invalid ip in %q: %w", v, err)
	}
	p, err := proto.Parse(protoExpr)
	if err != nil {
		return ipPortMember{}, fmt.Errorf("invalid proto in %q: %w", v, err)
	}
	parsedPort, err := port.Parse(portExpr)
	if err != nil {
		return ipPortMember{}, fmt.Errorf("invalid port in %q: %w", v, err)
	}
	start := parsedPort.Number
	end := parsedPort.Number
	if parsedPort.IsRange() {
		end = parsedPort.End
	}
	return ipPortMember{
		net:   ipnet,
		proto: *p,
		start: start,
		end:   end,
	}, nil
}

func parseIPOrCIDR(v string) (*net.IPNet, error) {
	if _, ipnet, err := net.ParseCIDR(v); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP/CIDR %q", v)
	}
	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
