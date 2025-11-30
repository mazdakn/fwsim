package link

import "github.com/mazdakn/fwsim/pkg/traffic"

type Link struct {
	link chan []traffic.Packet
}

func New() *Link {
	return &Link{
		link: make(chan []traffic.Packet),
	}
}
