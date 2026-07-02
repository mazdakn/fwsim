package config

import (
	"github.com/mazdakn/firecore/set"
	"github.com/mazdakn/firecore/table"
)

// Resource holds all parsed firewall resources (tables, sets, and intents).
type Resource struct {
	Tables  []*table.Table
	Sets    map[string]set.Set
	Intents []*Intent
}
