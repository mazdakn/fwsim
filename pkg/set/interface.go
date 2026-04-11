package set

import "github.com/mazdakn/fwsim/pkg/packet"

type Set interface {
	Add(string) error
	Match(*packet.Packet) bool
}
