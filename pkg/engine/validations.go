package engine

import "github.com/sirupsen/logrus"

func (e *Engine) Validate() {
	e.validateExpectations()
	e.validateAllRulesUsed()
}

func (e *Engine) validateExpectations() {
	for index, exp := range e.config.Expectations {
		/*if exp.Packet == nil {
			logrus.Errorf("Expectation %d has no packet - Skipping.", index)
			continue
		}*/

		pkt := packetFromExpectation(&exp)

		_, r := e.Match(pkt)
		if r == nil {
			logrus.Infof("no rule matched packet %s", exp.Packet)
			continue
		}
		expA := r.Action.String()
		expB := exp.Verdict

		if expA == expB {
			logrus.Infof("Expectation %d met", index)
		} else {
			logrus.Errorf("Expectation %d not met", index)
		}
	}
}

func (e *Engine) validateAllRulesUsed() {
	for i, r := range e.rules {
		if r.PacketCount() == 0 {
			logrus.Infof("Rule %v not used", i)
		}
	}
}
