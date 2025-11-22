package node

import (
	"net"
	"testing"

	. "github.com/onsi/gomega"
)

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
		node := NewNode(WithEndpoints("endpoint1", "endpoint2"))
		Expect(node.Name).To(BeEmpty())
		Expect(node.IPv4).To(BeNil())
		Expect(node.IPv6).To(BeNil())
		Expect(node.Endpoints).To(Equal([]string{"endpoint1", "endpoint2"}))
	})

	t.Run("node with all fields", func(t *testing.T) {
		node := NewNode(
			WithName("test-node"),
			WithIPv4("10.0.0.1"),
			WithIPv6("fe80::1"),
			WithEndpoints("ep1", "ep2", "ep3"),
		)
		Expect(node.Name).To(Equal("test-node"))
		Expect(node.IPv4).To(Equal(net.ParseIP("10.0.0.1")))
		Expect(node.IPv6).To(Equal(net.ParseIP("fe80::1")))
		Expect(node.Endpoints).To(Equal([]string{"ep1", "ep2", "ep3"}))
	})

	t.Run("node with multiple endpoint calls", func(t *testing.T) {
		node := NewNode(
			WithEndpoints("ep1", "ep2"),
			WithEndpoints("ep3"),
		)
		Expect(node.Endpoints).To(Equal([]string{"ep1", "ep2", "ep3"}))
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
		node := NewNode(
			WithName("test-node"),
			WithIPv4("192.168.1.1"),
			WithIPv6("2001:db8::1"),
			WithEndpoints("ep1", "ep2"),
		)
		str := node.String()
		Expect(str).To(Equal("Node{Name: test-node, IPv4: 192.168.1.1, IPv6: 2001:db8::1, Endpoints: [ep1 ep2]}"))
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
		node := NewNode(WithEndpoints("endpoint1", "endpoint2"))
		str := node.String()
		Expect(str).To(Equal("Node{Name: , IPv4: <nil>, IPv6: <nil>, Endpoints: [endpoint1 endpoint2]}"))
	})
}
