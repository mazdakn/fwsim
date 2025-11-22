package node

import (
	"fmt"
	"net"
)

type EndpointOption func(*Endpoint)

func WithEndpointName(name string) EndpointOption {
	return func(e *Endpoint) {
		e.Name = name
	}
}

func WithEndpointIPv4(addr string) EndpointOption {
	return func(e *Endpoint) {
		e.IPv4 = net.ParseIP(addr)
	}
}

func WithEndpointIPv6(addr string) EndpointOption {
	return func(e *Endpoint) {
		e.IPv6 = net.ParseIP(addr)
	}
}

func NewEndpoint(opts ...EndpointOption) *Endpoint {
	var e Endpoint
	for _, o := range opts {
		o(&e)
	}
	return &e
}

type Endpoint struct {
	Name string
	IPv4 net.IP
	IPv6 net.IP
}

func (e *Endpoint) String() string {
	ipv4Str := "<nil>"
	if e.IPv4 != nil {
		ipv4Str = e.IPv4.String()
	}
	ipv6Str := "<nil>"
	if e.IPv6 != nil {
		ipv6Str = e.IPv6.String()
	}
	return fmt.Sprintf("Endpoint{Name: %s, IPv4: %s, IPv6: %s}",
		e.Name, ipv4Str, ipv6Str)
}

type NodeOption func(*Node)

func WithName(name string) NodeOption {
	return func(n *Node) {
		n.Name = name
	}
}

func WithIPv4(addr string) NodeOption {
	return func(n *Node) {
		n.IPv4 = net.ParseIP(addr)
	}
}

func WithIPv6(addr string) NodeOption {
	return func(n *Node) {
		n.IPv6 = net.ParseIP(addr)
	}
}

func WithEndpoints(endpoints ...*Endpoint) NodeOption {
	return func(n *Node) {
		n.Endpoints = append(n.Endpoints, endpoints...)
	}
}

func NewNode(opts ...NodeOption) *Node {
	var n Node
	for _, o := range opts {
		o(&n)
	}
	return &n
}

type Node struct {
	Name      string
	IPv4      net.IP
	IPv6      net.IP
	Endpoints []*Endpoint
}

func (n *Node) String() string {
	ipv4Str := "<nil>"
	if n.IPv4 != nil {
		ipv4Str = n.IPv4.String()
	}
	ipv6Str := "<nil>"
	if n.IPv6 != nil {
		ipv6Str = n.IPv6.String()
	}
	return fmt.Sprintf("Node{Name: %s, IPv4: %s, IPv6: %s, Endpoints: %v}",
		n.Name, ipv4Str, ipv6Str, n.Endpoints)
}
