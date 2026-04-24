package config

import (
	"github.com/mazdakn/fwsim/pkg/set"
	"github.com/mazdakn/fwsim/pkg/table"
)

// Resource holds all parsed firewall resources (tables and sets).
type Resource struct {
	Tables []*table.Table
	Sets   map[string]set.Set
}
