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
rules:
  - name: allow-http
    dst:
      port: [80]
    action: Accept
`))
	Expect(err).To(BeNil())
	Expect(cfg.Name).To(Equal("app-table"))
	Expect(cfg.Order).To(Equal(uint64(100)))
	Expect(cfg.DefaultAction).To(Equal("Accept"))
	Expect(cfg.Rules).To(HaveLen(1))
}

func TestTableToTable(t *testing.T) {
	RegisterTestingT(t)

	cfg := &Table{
		Name:          "app-table",
		Order:         7,
		DefaultAction: "Drop",
		Rules: []TableRule{
			{
				Name:   "allow-http",
				Action: "Accept",
			},
		},
	}
	tbl, err := cfg.ToTable(nil)
	Expect(err).To(BeNil())
	Expect(tbl.Name).To(Equal("app-table"))
	Expect(tbl.Order).To(Equal(uint64(7)))
	Expect(tbl.DefaultAction.Action).To(Equal(rule.Drop))
	Expect(tbl.Rules).To(HaveLen(1))
	Expect(tbl.Rules[0].Action).To(Equal(rule.Accept))
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
