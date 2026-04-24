package match

import (
	"github.com/mazdakn/fwsim/pkg/packet"
	"github.com/mazdakn/fwsim/pkg/rule"
)

type MatchContext struct {
	Packet  *packet.Packet
	Verdict *rule.Action
	Trace   []*rule.Rule

	// ExpectedVerdict is the verdict expected by the intent. When nil, verdict
	// validation is skipped.
	ExpectedVerdict *rule.Action
	// HitByRule is the name of the rule expected to match the packet. When non-empty,
	// it is checked against the last rule recorded in Trace after matching.
	HitByRule string
}

type MatchContextOption func(*MatchContext)

// WithExpectedVerdict sets the verdict the intent expects the packet to receive.
func WithExpectedVerdict(a rule.Action) MatchContextOption {
	return func(m *MatchContext) {
		m.ExpectedVerdict = &a
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
		Packet: pkt,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// VerdictString returns a human-readable string for the verdict.
// Returns "no match" when Verdict is nil (no rule matched).
func (m *MatchContext) VerdictString() string {
	if m.Verdict == nil {
		return "no match"
	}
	return m.Verdict.String()
}

// VerdictMatches reports whether the actual verdict satisfies the intent.
// Returns true when no expected verdict was specified (nil).
func (m *MatchContext) VerdictMatches() bool {
	if m.ExpectedVerdict == nil {
		return true
	}
	if m.Verdict == nil {
		return false
	}
	return *m.ExpectedVerdict == *m.Verdict
}

// RuleMatches reports whether the expected rule was the decisive rule that
// determined the verdict. Returns true when no expected rule was specified.
// Returns false when the verdict is nil (no rule fired).
func (m *MatchContext) RuleMatches() bool {
	if m.HitByRule == "" {
		return true
	}
	if m.Verdict == nil || len(m.Trace) == 0 {
		return false
	}
	return m.Trace[len(m.Trace)-1].Name == m.HitByRule
}
