package policy

import (
	"github.com/mazdakn/fwsim/pkg/traffic"
	"github.com/sirupsen/logrus"
)

type Store struct {
	rules []Rule
}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Match(pkt *traffic.Packet) (int, *Rule) {
	logrus.Debugf("Matching packet %+v", pkt)
	for i, r := range s.rules {
		if r.match(pkt) {
			logrus.Debugf("Rule %+v matched", r)
			return i, &r
		}
	}
	logrus.Debug("No rule matched")
	return -1, nil
}
