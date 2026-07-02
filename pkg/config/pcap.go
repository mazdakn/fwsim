package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/mazdakn/firecore/port"
	"github.com/mazdakn/firecore/proto"
)

func ConfigIntentsFromPCAPFile(file string) ([]*Intent, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", file, err)
	}
	defer func() {
		_ = f.Close()
	}()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read pcap file %s: %w", file, err)
	}

	intents := []*Intent{}
	source := filepath.Base(file)
	for packetIndex := 1; ; packetIndex++ {
		data, _, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read packet %d from %s: %w", packetIndex, file, err)
		}

		intent, err := intentFromPCAPPacket(data, reader.LinkType(), source, packetIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode packet %d from %s: %w", packetIndex, file, err)
		}
		intents = append(intents, intent)
	}

	if len(intents) == 0 {
		return nil, fmt.Errorf("no packets found in pcap file %s", file)
	}

	return intents, nil
}

func intentFromPCAPPacket(data []byte, linkType layers.LinkType, source string, packetIndex int) (*Intent, error) {
	decoded := gopacket.NewPacket(data, linkType, gopacket.Default)
	if errLayer := decoded.ErrorLayer(); errLayer != nil {
		return nil, errLayer.Error()
	}

	intentName := fmt.Sprintf("%s#%d", source, packetIndex)
	packetConfig, err := packetFromDecodedPacket(decoded)
	if err != nil {
		return nil, err
	}

	return &Intent{
		Name:   intentName,
		Packet: packetConfig,
	}, nil
}

func packetFromDecodedPacket(decoded gopacket.Packet) (Packet, error) {
	packetConfig := Packet{}

	switch {
	case decoded.Layer(layers.LayerTypeIPv4) != nil:
		ipv4 := decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		packetConfig.SrcAddr = ipv4.SrcIP.String()
		packetConfig.DstAddr = ipv4.DstIP.String()
		packetConfig.Proto = proto.Proto(ipv4.Protocol)
	case decoded.Layer(layers.LayerTypeIPv6) != nil:
		ipv6 := decoded.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		packetConfig.SrcAddr = ipv6.SrcIP.String()
		packetConfig.DstAddr = ipv6.DstIP.String()
		packetConfig.Proto = proto.Proto(ipv6.NextHeader)
	default:
		return Packet{}, fmt.Errorf("packet is not IPv4 or IPv6")
	}

	switch {
	case decoded.Layer(layers.LayerTypeTCP) != nil:
		tcp := decoded.Layer(layers.LayerTypeTCP).(*layers.TCP)
		packetConfig.SrcPort = port.Port{Number: uint16(tcp.SrcPort)}
		packetConfig.DstPort = port.Port{Number: uint16(tcp.DstPort)}
	case decoded.Layer(layers.LayerTypeUDP) != nil:
		udp := decoded.Layer(layers.LayerTypeUDP).(*layers.UDP)
		packetConfig.SrcPort = port.Port{Number: uint16(udp.SrcPort)}
		packetConfig.DstPort = port.Port{Number: uint16(udp.DstPort)}
	}

	return packetConfig, nil
}
