package model

type Result struct {
	EnforcedBy *Rule
	Trace      []*Rule
}
