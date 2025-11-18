package traffic

import (
	"fmt"
	"net"
)

type Packet struct {
	SrcAddr  net.IP
	DstAddr  net.IP
	Protocol uint8

	SrcPort uint16
	DstPort uint16
}

func (p *Packet) String() string {
	return fmt.Sprintf("%d %s:%d -> %s:%d", p.Protocol, p.SrcAddr.String(), p.SrcPort,
		p.DstAddr.String(), p.DstPort)
}
