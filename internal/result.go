package model

import "github.com/mazdakn/fwsim/internal/rule"

// Result holds the outcome of matching a packet against a Table.
type Result struct {
	Verdict rule.Action
	Trace   []*rule.Rule
}
