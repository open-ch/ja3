package main

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/open-ch/ja3"
	"io"
	"os"
)

// Reader provides an uniform interface when reading from different sources for the command line interface.
type Reader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// ReadPcapFile returns a reader for the supplied pcap file.
func ReadPcapFile(file *os.File) (Reader, error) {
	return pcapgo.NewReader(file)
}

// ReadPcapngFile returns a reader for the supplied pcapng file.
func ReadPcapngFile(file *os.File) (Reader, error) {
	return pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
}

// ReadFromInterface returns a handle to read from the specified interface. The snap length is set to 1600 and the
// interface is in promiscuous mode.
func ReadFromInterface(device string) (Reader, error) {
	return pcap.OpenLive(device, 1600, true, pcap.BlockForever)
}

// ComputeJA3FromReader reads from reader until an io.EOF error is encountered and writes verbose information about
// the found Client Hellos in the stream in JSON format to the writer.
func ComputeJA3FromReader(reader Reader, writer io.Writer) error {

	// Build a selective parser which only decodes the needed layers
	var ethernet layers.Ethernet
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var decoded []gopacket.LayerType
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernet, &ipv4, &ipv6, &tcp)

	for {
		// Read packet data
		packet, ci, err := reader.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		// Decode the packet with our predefined parser
		parser.DecodeLayers(packet, &decoded)
		// Check if we could decode up to the TCP layer
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeTCP:

				j, err := ja3.ComputeJA3FromSegment(tcp.Payload)
				// Check if the parsing was successful, else segment is no Client Hello
				if err != nil {
					continue
				}

				// Prepare capture info for JSON marshalling
				var srcIP, dstIP string
				for _, layerType := range decoded {
					switch layerType {
					case layers.LayerTypeIPv4:
						srcIP = ipv4.SrcIP.String()
						dstIP = ipv4.DstIP.String()
					case layers.LayerTypeIPv6:
						srcIP = ipv6.SrcIP.String()
						dstIP = ipv6.DstIP.String()
					}
				}

				err = writeJSON(dstIP, int(tcp.DstPort), srcIP, int(tcp.SrcPort), ci.Timestamp.UnixNano(), j, writer)
				if err != nil {
					return err
				}

			}
		}
	}
	return nil
}

func CompatComputeJA3FromReader(reader Reader, writer io.Writer) error {
	for {
		// Read packet data
		packetData, ci, err := reader.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true, Lazy: true})

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			j, err := ja3.ComputeJA3FromSegment(tcp.Payload)
			// Check if the parsing was successful, else segment is no Client Hello
			if err != nil {
				continue
			}

			// Prepare capture info for JSON marshalling
			src, dst := packet.NetworkLayer().NetworkFlow().Endpoints()

			err = writeJSON(dst.String(), int(tcp.DstPort), src.String(), int(tcp.SrcPort), ci.Timestamp.UnixNano(), j, writer)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// writeJSON to writer
func writeJSON(dstIP string, dstPort int, srcIP string, srcPort int, timestamp int64, j *ja3.JA3, writer io.Writer) error {
	// Use the same convention as in the official python implementation
	js, err := json.Marshal(struct {
		DstIP     string `json:"destination_ip"`
		DstPort   int    `json:"destination_port"`
		JA3String string `json:"ja3"`
		JA3Hash   string `json:"ja3_digest"`
		SrcIP     string `json:"source_ip"`
		SrcPort   int    `json:"source_port"`
		SNI       string `json:"sni"`
		Timestamp int64  `json:"timestamp"`
	}{
		dstIP,
		dstPort,
		string(j.GetJA3String()),
		j.GetJA3Hash(),
		srcIP,
		srcPort,
		j.GetSNI(),
		timestamp,
	})
	if err != nil {
		return err
	}

	// Write the JSON to the writer
	writer.Write(js)
	writer.Write([]byte("\n"))
	return nil
}
