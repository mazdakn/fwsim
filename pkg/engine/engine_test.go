package engine

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/config"
	"github.com/mazdakn/fwsim/pkg/match"
	"github.com/mazdakn/fwsim/pkg/proto"
	"github.com/mazdakn/fwsim/pkg/rule"
	. "github.com/onsi/gomega"
)

const testRulesYAML = `
rules:
  - name: allow-192.168-to-1.1.1.1
    src_net: [192.168.1.0/24]
    dst_net: [1.1.1.1/32]
    dst_port: [80]
    src_port: [30000]
    proto: [7]
    action: Accept
  - name: deny-access-http
    dst_net: [1.1.1.1/32]
    dst_port: [80]
    proto: [7]
    action: Drop
  - name: deny-tcp-8080
    dst_net: [2.2.2.2/32]
    dst_port: [8080]
    proto: [7]
    action: Drop
default_action: Accept
`

const testPacketsYAML = `
packets:
  - name: access backend
    src_addr: 192.168.1.5
    dst_addr: 1.1.1.1
    proto: 7
    src_port: 30000
    dst_port: 80
  - name: access app1
    src_addr: 10.0.0.1
    dst_addr: 2.2.2.2
    proto: 7
    src_port: 12345
    dst_port: 8080
  - name: dns traffic
    src_addr: 172.16.0.1
    dst_addr: 8.8.8.8
    proto: 17
    src_port: 54321
    dst_port: 53
  - name: access backend
    src_addr: 192.168.1.5
    dst_addr: 1.1.1.1
    proto: 7
    src_port: 30000
    dst_port: 80
  - name: dns traffic
    src_addr: 172.16.0.1
    dst_addr: 8.8.8.8
    proto: 17
    src_port: 54321
    dst_port: 53
`

const testSetsYAML = `
sets:
  - name: trusted-ips
    type: ip
    members:
      - 192.168.1.0/24
      - 10.0.0.0/8
  - name: web-ports
    type: port
    members:
      - "80"
      - "443"
      - "8080"
  - name: allowed-protos
    type: proto
    members:
      - tcp
      - udp
`

func TestNew(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	Expect(engine).ToNot(BeNil())
}

func TestPacketsFromBytesAndMatch(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigRulesFromBytes([]byte(testRulesYAML))
	Expect(err).To(BeNil())

	pkts, err := config.PacketsFromBytes([]byte(testPacketsYAML))
	Expect(err).To(BeNil())
	Expect(len(pkts)).To(Equal(5))

	// First packet: src 192.168.1.5 -> dst 1.1.1.1:80 proto 7, src_port 30000 — matches rule 1 (Accept)
	m := &match.Match{Packet: pkts[0]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))

	// Second packet: src 10.0.0.1 -> dst 2.2.2.2:8080 proto 7 — matches rule 3 (Drop)
	m = &match.Match{Packet: pkts[1]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Drop))

	// Third packet: proto 17, no matching rule — default action Accept
	m = &match.Match{Packet: pkts[2]}
	engine.RunTest(m)
	Expect(m.Result.Verdict).To(Equal(rule.Accept))
}

func TestLoadSetsFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigRulesFromBytes([]byte(testRulesYAML))
	Expect(err).To(BeNil())

	err = engine.ConfigSetsFromBytes([]byte(testSetsYAML))
	Expect(err).To(BeNil())

	sets := engine.Sets()
	Expect(sets).To(HaveLen(3))
	Expect(sets).To(HaveKey("trusted-ips"))
	Expect(sets).To(HaveKey("web-ports"))
	Expect(sets).To(HaveKey("allowed-protos"))
}

func TestLoadRulesFromBytes(t *testing.T) {
	RegisterTestingT(t)

	engine := New(Config{})
	err := engine.ConfigRulesFromBytes([]byte(testRulesYAML))
	Expect(err).To(BeNil())

	Expect(len(engine.table.Rules)).To(Equal(3))

	// Verify first rule
	rule1 := engine.table.Rules[0]
	Expect(rule1.SrcNet).ToNot(BeNil())
	Expect(rule1.SrcNet.String()).To(Equal("192.168.1.0/24"))
	Expect(rule1.DstNet).ToNot(BeNil())
	Expect(rule1.DstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(rule1.Proto).ToNot(BeNil())
	Expect(rule1.Proto.Match(proto.Proto(7))).To(BeTrue())
	Expect(rule1.Action.String()).To(Equal("Accept"))

	// Verify second rule
	rule2 := engine.table.Rules[1]
	Expect(rule2.DstNet).ToNot(BeNil())
	Expect(rule2.DstNet.String()).To(Equal("1.1.1.1/32"))
	Expect(rule2.Proto).ToNot(BeNil())
	Expect(rule2.Proto.Match(proto.Proto(7))).To(BeTrue())
	Expect(rule2.Action.String()).To(Equal("Drop"))

	// Verify default action is set
	Expect(engine.table.DefaultAction.Action.String()).To(Equal("Accept"))
}
