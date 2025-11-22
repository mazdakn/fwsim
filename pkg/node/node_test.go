package node

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"
)

func TestNewEndpoint(t *testing.T) {
	RegisterTestingT(t)

	t.Run("empty endpoint", func(t *testing.T) {
		ep := NewEndpoint()
		Expect(ep).ToNot(BeNil())
		Expect(ep.Name).To(BeEmpty())
		Expect(ep.IPv4).To(BeNil())
		Expect(ep.IPv6).To(BeNil())
	})

	t.Run("endpoint with name", func(t *testing.T) {
		ep := NewEndpoint(WithEndpointName("eth0"))
		Expect(ep.Name).To(Equal("eth0"))
		Expect(ep.IPv4).To(BeNil())
		Expect(ep.IPv6).To(BeNil())
	})

	t.Run("endpoint with IPv4", func(t *testing.T) {
		ep := NewEndpoint(WithEndpointIPv4("192.168.1.1"))
		Expect(ep.Name).To(BeEmpty())
		Expect(ep.IPv4).To(Equal(net.ParseIP("192.168.1.1")))
		Expect(ep.IPv6).To(BeNil())
	})

	t.Run("endpoint with IPv6", func(t *testing.T) {
		ep := NewEndpoint(WithEndpointIPv6("fe80::1"))
		Expect(ep.Name).To(BeEmpty())
		Expect(ep.IPv4).To(BeNil())
		Expect(ep.IPv6).To(Equal(net.ParseIP("fe80::1")))
	})

	t.Run("endpoint with all fields", func(t *testing.T) {
		ep := NewEndpoint(
			WithEndpointName("eth0"),
			WithEndpointIPv4("10.0.0.1"),
			WithEndpointIPv6("fe80::1"),
		)
		Expect(ep.Name).To(Equal("eth0"))
		Expect(ep.IPv4).To(Equal(net.ParseIP("10.0.0.1")))
		Expect(ep.IPv6).To(Equal(net.ParseIP("fe80::1")))
	})
}

func TestEndpointString(t *testing.T) {
	RegisterTestingT(t)

	t.Run("empty endpoint", func(t *testing.T) {
		ep := NewEndpoint()
		str := ep.String()
		Expect(str).To(Equal("Endpoint{Name: , IPv4: <nil>, IPv6: <nil>}"))
	})

	t.Run("endpoint with name only", func(t *testing.T) {
		ep := NewEndpoint(WithEndpointName("eth0"))
		str := ep.String()
		Expect(str).To(Equal("Endpoint{Name: eth0, IPv4: <nil>, IPv6: <nil>}"))
	})

	t.Run("endpoint with all fields", func(t *testing.T) {
		ep := NewEndpoint(
			WithEndpointName("eth0"),
			WithEndpointIPv4("192.168.1.1"),
			WithEndpointIPv6("fe80::1"),
		)
		str := ep.String()
		Expect(str).To(Equal("Endpoint{Name: eth0, IPv4: 192.168.1.1, IPv6: fe80::1}"))
	})
}

func TestNewNode(t *testing.T) {
	RegisterTestingT(t)

	t.Run("empty node", func(t *testing.T) {
		node := NewNode()
		Expect(node).ToNot(BeNil())
		Expect(node.Name).To(BeEmpty())
		Expect(node.IPv4).To(BeNil())
		Expect(node.IPv6).To(BeNil())
		Expect(node.Endpoints).To(BeEmpty())
	})

	t.Run("node with name", func(t *testing.T) {
		node := NewNode(WithName("test-node"))
		Expect(node.Name).To(Equal("test-node"))
		Expect(node.IPv4).To(BeNil())
		Expect(node.IPv6).To(BeNil())
		Expect(node.Endpoints).To(BeEmpty())
	})

	t.Run("node with IPv4", func(t *testing.T) {
		node := NewNode(WithIPv4("192.168.1.1"))
		Expect(node.Name).To(BeEmpty())
		Expect(node.IPv4).To(Equal(net.ParseIP("192.168.1.1")))
		Expect(node.IPv6).To(BeNil())
		Expect(node.Endpoints).To(BeEmpty())
	})

	t.Run("node with IPv6", func(t *testing.T) {
		node := NewNode(WithIPv6("2001:db8::1"))
		Expect(node.Name).To(BeEmpty())
		Expect(node.IPv4).To(BeNil())
		Expect(node.IPv6).To(Equal(net.ParseIP("2001:db8::1")))
		Expect(node.Endpoints).To(BeEmpty())
	})

	t.Run("node with endpoints", func(t *testing.T) {
		ep1 := NewEndpoint(WithEndpointName("eth0"))
		ep2 := NewEndpoint(WithEndpointName("eth1"))
		node := NewNode(WithEndpoints(ep1, ep2))
		Expect(node.Name).To(BeEmpty())
		Expect(node.IPv4).To(BeNil())
		Expect(node.IPv6).To(BeNil())
		Expect(node.Endpoints).To(HaveLen(2))
		Expect(node.Endpoints[0].Name).To(Equal("eth0"))
		Expect(node.Endpoints[1].Name).To(Equal("eth1"))
	})

	t.Run("node with all fields", func(t *testing.T) {
		ep1 := NewEndpoint(
			WithEndpointName("eth0"),
			WithEndpointIPv4("10.0.0.10"),
			WithEndpointIPv6("fe80::10"),
		)
		ep2 := NewEndpoint(
			WithEndpointName("eth1"),
			WithEndpointIPv4("10.0.0.11"),
			WithEndpointIPv6("fe80::11"),
		)
		node := NewNode(
			WithName("test-node"),
			WithIPv4("10.0.0.1"),
			WithIPv6("fe80::1"),
			WithEndpoints(ep1, ep2),
		)
		Expect(node.Name).To(Equal("test-node"))
		Expect(node.IPv4).To(Equal(net.ParseIP("10.0.0.1")))
		Expect(node.IPv6).To(Equal(net.ParseIP("fe80::1")))
		Expect(node.Endpoints).To(HaveLen(2))
		Expect(node.Endpoints[0].Name).To(Equal("eth0"))
		Expect(node.Endpoints[0].IPv4).To(Equal(net.ParseIP("10.0.0.10")))
		Expect(node.Endpoints[0].IPv6).To(Equal(net.ParseIP("fe80::10")))
		Expect(node.Endpoints[1].Name).To(Equal("eth1"))
		Expect(node.Endpoints[1].IPv4).To(Equal(net.ParseIP("10.0.0.11")))
		Expect(node.Endpoints[1].IPv6).To(Equal(net.ParseIP("fe80::11")))
	})

	t.Run("node with multiple endpoint calls", func(t *testing.T) {
		ep1 := NewEndpoint(WithEndpointName("eth0"))
		ep2 := NewEndpoint(WithEndpointName("eth1"))
		ep3 := NewEndpoint(WithEndpointName("eth2"))
		node := NewNode(
			WithEndpoints(ep1, ep2),
			WithEndpoints(ep3),
		)
		Expect(node.Endpoints).To(HaveLen(3))
		Expect(node.Endpoints[0].Name).To(Equal("eth0"))
		Expect(node.Endpoints[1].Name).To(Equal("eth1"))
		Expect(node.Endpoints[2].Name).To(Equal("eth2"))
	})
}

func TestNodeString(t *testing.T) {
	RegisterTestingT(t)

	t.Run("empty node", func(t *testing.T) {
		node := NewNode()
		str := node.String()
		Expect(str).To(Equal("Node{Name: , IPv4: <nil>, IPv6: <nil>, Endpoints: []}"))
	})

	t.Run("node with name only", func(t *testing.T) {
		node := NewNode(WithName("test-node"))
		str := node.String()
		Expect(str).To(Equal("Node{Name: test-node, IPv4: <nil>, IPv6: <nil>, Endpoints: []}"))
	})

	t.Run("node with all fields", func(t *testing.T) {
		ep1 := NewEndpoint(
			WithEndpointName("eth0"),
			WithEndpointIPv4("192.168.1.10"),
			WithEndpointIPv6("fe80::10"),
		)
		ep2 := NewEndpoint(
			WithEndpointName("eth1"),
			WithEndpointIPv4("192.168.1.11"),
			WithEndpointIPv6("fe80::11"),
		)
		node := NewNode(
			WithName("test-node"),
			WithIPv4("192.168.1.1"),
			WithIPv6("2001:db8::1"),
			WithEndpoints(ep1, ep2),
		)
		str := node.String()
		Expect(str).To(ContainSubstring("Node{Name: test-node, IPv4: 192.168.1.1, IPv6: 2001:db8::1"))
		Expect(str).To(ContainSubstring("Endpoint{Name: eth0, IPv4: 192.168.1.10, IPv6: fe80::10}"))
		Expect(str).To(ContainSubstring("Endpoint{Name: eth1, IPv4: 192.168.1.11, IPv6: fe80::11}"))
	})

	t.Run("node with IPv4 only", func(t *testing.T) {
		node := NewNode(WithIPv4("10.0.0.1"))
		str := node.String()
		Expect(str).To(Equal("Node{Name: , IPv4: 10.0.0.1, IPv6: <nil>, Endpoints: []}"))
	})

	t.Run("node with IPv6 only", func(t *testing.T) {
		node := NewNode(WithIPv6("fe80::1"))
		str := node.String()
		Expect(str).To(Equal("Node{Name: , IPv4: <nil>, IPv6: fe80::1, Endpoints: []}"))
	})

	t.Run("node with endpoints only", func(t *testing.T) {
		ep1 := NewEndpoint(WithEndpointName("eth0"))
		ep2 := NewEndpoint(WithEndpointName("eth1"))
		node := NewNode(WithEndpoints(ep1, ep2))
		str := node.String()
		Expect(str).To(ContainSubstring("Node{Name: , IPv4: <nil>, IPv6: <nil>"))
		Expect(str).To(ContainSubstring("Endpoint{Name: eth0"))
		Expect(str).To(ContainSubstring("Endpoint{Name: eth1"))
	})
}
