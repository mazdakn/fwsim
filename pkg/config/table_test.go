package config

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/rule"
	. "github.com/onsi/gomega"
)

func TestTableFromBytes(t *testing.T) {
	RegisterTestingT(t)

	cfg, err := TableFromBytes([]byte(`
name: app-table
order: 100
default_action: Accept
`))
	Expect(err).To(BeNil())
	Expect(cfg.Name).To(Equal("app-table"))
	Expect(cfg.Order).To(Equal(uint64(100)))
	Expect(cfg.DefaultAction).To(Equal("Accept"))
}

func TestTableToTable(t *testing.T) {
	RegisterTestingT(t)

	cfg := &Table{
		Name:          "app-table",
		Order:         7,
		DefaultAction: "Drop",
	}
	tbl, err := cfg.ToTable()
	Expect(err).To(BeNil())
	Expect(tbl.Name).To(Equal("app-table"))
	Expect(tbl.Order).To(Equal(uint64(7)))
	Expect(tbl.DefaultAction.Action).To(Equal(rule.Drop))
}

func TestTableFromBytesInvalidDefaultAction(t *testing.T) {
	RegisterTestingT(t)

	cfg, err := TableFromBytes([]byte(`
name: app-table
order: 100
default_action: reject
`))
	Expect(err).ToNot(BeNil())
	Expect(cfg).To(BeNil())
}
