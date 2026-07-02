package config_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/mazdakn/firecore/conntrack"
	"github.com/mazdakn/firecore/proto"
	"github.com/mazdakn/firecore/rule"
	"github.com/mazdakn/firecore/table"
	"github.com/mazdakn/fwsim/pkg/config"
	enginepkg "github.com/mazdakn/fwsim/pkg/engine"
	. "github.com/onsi/gomega"
)

type pcapPacketSpec struct {
	srcIP   string
	dstIP   string
	proto   layers.IPProtocol
	srcPort uint16
	dstPort uint16
}

func TestConfigIntentsFromPCAPFile(t *testing.T) {
	RegisterTestingT(t)

	file := filepath.Join(t.TempDir(), "traffic.pcap")
	writePCAP(t, file, []pcapPacketSpec{
		{
			srcIP:   "10.0.0.1",
			dstIP:   "1.1.1.1",
			proto:   layers.IPProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
		},
		{
			srcIP:   "10.0.0.2",
			dstIP:   "8.8.8.8",
			proto:   layers.IPProtocolUDP,
			srcPort: 53000,
			dstPort: 53,
		},
	})

	intents, err := config.ConfigIntentsFromPCAPFile(file)
	Expect(err).To(BeNil())
	Expect(intents).To(HaveLen(2))

	Expect(intents[0].Name).To(Equal("traffic.pcap#1"))
	Expect(intents[0].Packet.SrcAddr).To(Equal("10.0.0.1"))
	Expect(intents[0].Packet.DstAddr).To(Equal("1.1.1.1"))
	Expect(intents[0].Packet.Proto).To(Equal(proto.TCP))
	Expect(intents[0].Packet.SrcPort.Number).To(Equal(uint16(12345)))
	Expect(intents[0].Packet.DstPort.Number).To(Equal(uint16(80)))

	Expect(intents[1].Name).To(Equal("traffic.pcap#2"))
	Expect(intents[1].Packet.Proto).To(Equal(proto.UDP))
	Expect(intents[1].Packet.SrcPort.Number).To(Equal(uint16(53000)))
	Expect(intents[1].Packet.DstPort.Number).To(Equal(uint16(53)))
}

func TestConfigIntentsFromPCAPFileRejectsNonIPPackets(t *testing.T) {
	RegisterTestingT(t)

	file := filepath.Join(t.TempDir(), "arp-only.pcap")
	writeARPPcap(t, file)

	intents, err := config.ConfigIntentsFromPCAPFile(file)
	Expect(err).ToNot(BeNil())
	Expect(err.Error()).To(ContainSubstring("packet is not IPv4 or IPv6"))
	Expect(intents).To(BeNil())
}

func TestConfigIntentsFromPCAPFilePreservesPacketOrderForConntrack(t *testing.T) {
	RegisterTestingT(t)

	file := filepath.Join(t.TempDir(), "stateful.pcap")
	writePCAP(t, file, []pcapPacketSpec{
		{
			srcIP:   "10.0.0.1",
			dstIP:   "1.1.1.1",
			proto:   layers.IPProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
		},
		{
			srcIP:   "1.1.1.1",
			dstIP:   "10.0.0.1",
			proto:   layers.IPProtocolTCP,
			srcPort: 80,
			dstPort: 12345,
		},
	})

	intents, err := config.ConfigIntentsFromPCAPFile(file)
	Expect(err).To(BeNil())

	tbl, err := config.ConfigTableFromBytes([]byte(`
name: stateful
chains:
  - name: default
    rules:
      - name: allow-new-http
        ct_state: [new]
        dst:
          port: [80]
        proto: [6]
        action: Accept
      - name: allow-established
        ct_state: [established]
        proto: [6]
        action: Accept
default_action: Drop
`), nil)
	Expect(err).To(BeNil())

	results := enginepkg.New(&config.Resource{
		Tables:  []*table.Table{tbl},
		Intents: intents,
	}).RunTests()

	Expect(results).To(HaveLen(2))
	Expect(results[0].ConnState).To(Equal(conntrack.StateNew))
	Expect(results[0].Verdict).To(HaveValue(Equal(rule.Accept)))
	Expect(results[1].ConnState).To(Equal(conntrack.StateEstablished))
	Expect(results[1].Verdict).To(HaveValue(Equal(rule.Accept)))
}

func writePCAP(t *testing.T, file string, packets []pcapPacketSpec) {
	t.Helper()

	f, err := os.Create(file)
	Expect(err).To(BeNil())
	defer func() {
		err := f.Close()
		Expect(err).To(BeNil())
	}()

	writer := pcapgo.NewWriter(f)
	Expect(writer.WriteFileHeader(65536, layers.LinkTypeEthernet)).To(Succeed())

	for i, spec := range packets {
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
			DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ipv4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    net.ParseIP(spec.srcIP).To4(),
			DstIP:    net.ParseIP(spec.dstIP).To4(),
			Protocol: spec.proto,
		}

		serializableLayers := []gopacket.SerializableLayer{eth, ipv4}
		switch spec.proto {
		case layers.IPProtocolTCP:
			tcp := &layers.TCP{
				SrcPort: layers.TCPPort(spec.srcPort),
				DstPort: layers.TCPPort(spec.dstPort),
				SYN:     true,
			}
			Expect(tcp.SetNetworkLayerForChecksum(ipv4)).To(Succeed())
			serializableLayers = append(serializableLayers, tcp)
		case layers.IPProtocolUDP:
			udp := &layers.UDP{
				SrcPort: layers.UDPPort(spec.srcPort),
				DstPort: layers.UDPPort(spec.dstPort),
			}
			Expect(udp.SetNetworkLayerForChecksum(ipv4)).To(Succeed())
			serializableLayers = append(serializableLayers, udp)
		case layers.IPProtocolICMPv4:
			serializableLayers = append(serializableLayers, &layers.ICMPv4{
				TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			})
		default:
			t.Fatalf("unsupported test protocol: %v", spec.proto)
		}

		Expect(gopacket.SerializeLayers(buffer, opts, serializableLayers...)).To(Succeed())
		data := buffer.Bytes()
		Expect(writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Unix(int64(i+1), 0),
			CaptureLength: len(data),
			Length:        len(data),
		}, data)).To(Succeed())
	}
}

func writeARPPcap(t *testing.T, file string) {
	t.Helper()

	f, err := os.Create(file)
	Expect(err).To(BeNil())
	defer func() {
		err := f.Close()
		Expect(err).To(BeNil())
	}()

	writer := pcapgo.NewWriter(f)
	Expect(writer.WriteFileHeader(65536, layers.LinkTypeEthernet)).To(Succeed())

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	Expect(gopacket.SerializeLayers(buffer, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
			SourceProtAddress: net.ParseIP("10.0.0.1").To4(),
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    net.ParseIP("10.0.0.2").To4(),
		},
	)).To(Succeed())

	data := buffer.Bytes()
	Expect(writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Unix(1, 0),
		CaptureLength: len(data),
		Length:        len(data),
	}, data)).To(Succeed())
}
