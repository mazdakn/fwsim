package model

// Result holds the outcome of matching a packet against a Table.
type Result struct {
	Verdict Action
	Trace   []*Rule
}
