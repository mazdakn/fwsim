package match

import (
	"fmt"
	"strings"

	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
)

type Verdict int

const Undefined Verdict = -1

const (
	Accept Verdict = iota
	Drop
	Pass
	NoMatch
)

// ParseVerdict converts a string to a Verdict. Returns Undefined and an error
// if the string is not a recognized verdict name.
func ParseVerdict(s string) (Verdict, error) {
	switch strings.ToLower(strings.ReplaceAll(s, "_", "")) {
	case "accept":
		return Accept, nil
	case "drop":
		return Drop, nil
	case "pass":
		return Pass, nil
	case "nomatch":
		return NoMatch, nil
	case "", "undefined":
		return Undefined, nil
	default:
		return Undefined, fmt.Errorf("unknown verdict: %s", s)
	}
}

func (v Verdict) String() string {
	switch v {
	case Accept:
		return "Accept"
	case Drop:
		return "Drop"
	case Pass:
		return "Pass"
	case NoMatch:
		return "no match"
	default:
		return fmt.Sprintf("Undefined(%d)", v)
	}
}

func VerdictFromAction(a rule.Action) Verdict {
	switch a {
	case rule.Accept:
		return Accept
	case rule.Drop:
		return Drop
	case rule.Pass:
		return Pass
	default:
		return Undefined
	}
}

type MatchContext struct {
	Packet  *packet.Packet
	Verdict Verdict
	Trace   []*rule.Rule

	// ExpectedVerdict is the verdict expected by the intent. When set to a value
	// other than Undefined, it is compared against the actual Verdict after matching.
	ExpectedVerdict Verdict
	// HitByRule is the name of the rule expected to match the packet. When non-empty,
	// it is checked against the last rule recorded in Trace after matching.
	HitByRule string
}

type MatchContextOption func(*MatchContext)

// WithExpectedVerdict sets the verdict the intent expects the packet to receive.
func WithExpectedVerdict(v Verdict) MatchContextOption {
	return func(m *MatchContext) {
		m.ExpectedVerdict = v
	}
}

// WithExpectedRule sets the name of the rule expected to be the decisive match.
func WithExpectedRule(name string) MatchContextOption {
	return func(m *MatchContext) {
		m.HitByRule = name
	}
}

func New(pkt *packet.Packet, opts ...MatchContextOption) *MatchContext {
	m := &MatchContext{
		Packet:          pkt,
		Verdict:         NoMatch,
		ExpectedVerdict: Undefined,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// VerdictMatches reports whether the actual verdict satisfies the intent.
// Returns true when no expected verdict was specified (Undefined).
func (m *MatchContext) VerdictMatches() bool {
	return m.ExpectedVerdict == Undefined || m.ExpectedVerdict == m.Verdict
}

// RuleMatches reports whether the expected rule was the decisive rule that
// determined the verdict. Returns true when no expected rule was specified.
// Returns false when the verdict is NoMatch (no rule fired).
func (m *MatchContext) RuleMatches() bool {
	if m.HitByRule == "" {
		return true
	}
	if m.Verdict == NoMatch || len(m.Trace) == 0 {
		return false
	}
	return m.Trace[len(m.Trace)-1].Name == m.HitByRule
}
