package policy

import (
	"testing"

	"github.com/mazdakn/fwsim/pkg/traffic"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestRuleMatch(t *testing.T) {
	RegisterTestingT(t)

	pkt := traffic.SamplePacket()

	shouldMatchTestCases := []*Rule{
		NewRule(),
		NewRule(WithProto(17)),
		NewRule(WithSrcPort(55555)),
		NewRule(WithDstPort(80)),
		NewRule(WithSrcNet("10.10.10.0/24")),
		NewRule(WithDstNet("1.1.1.1/32")),
		NewRule(WithProto(17), WithSrcPort(55555)),
		NewRule(WithProto(17), WithDstPort(80)),
		NewRule(WithSrcPort(55555), WithDstPort(80)),
		NewRule(WithDstPort(80), WithDstNet("1.1.1.1/32")),
		NewRule(WithProto(17), WithSrcPort(55555), WithDstPort(80), WithSrcNet("10.10.10.0/24"), WithDstNet("1.1.1.1/32")),
		NewRule(WithProto(17), WithDstPort(80), WithDstNet("1.1.1.1/32")),
	}

	shouldNotMatchTestCases := []*Rule{
		NewRule(WithProto(18), WithSrcPort(55555), WithDstPort(80), WithSrcNet("10.10.10.0/24"), WithDstNet("1.1.1.1/32")),
	}

	logrus.Infof("Packet %+v", pkt)
	for _, r := range shouldMatchTestCases {
		Expect(r.match(pkt)).To(BeTrue())
	}
	for _, r := range shouldNotMatchTestCases {
		Expect(r.match(pkt)).To(BeFalse())
	}
}
