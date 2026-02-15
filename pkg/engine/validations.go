package engine

import "github.com/sirupsen/logrus"

func (e *Engine) Validate() {
	e.ValidateExpectations()
}

func (e *Engine) ValidateExpectations() {
	for index, exp := range e.config.Expectations {
		if exp.Packet == nil {
			logrus.Errorf("Expectation %d has no packet - Skipping.", index)
			continue
		}

		_, r := e.Match(exp.Packet)
		expA := r.Action.String()
		expB := exp.Result

		if expA == expB {
			logrus.Infof("Expectation %d met", index)
		} else {
			logrus.Errorf("Expectation %d not met", index)
		}
	}
}
