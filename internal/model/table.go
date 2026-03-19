package model

// Table holds a slice of firewall rules.
type Table struct {
	Rules         []*Rule
	DefaultAction *Rule
}
