package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Layer2 struct {
	SrcMAC string `json:"src_mac"`
	DstMAC string `json:"dst_mac"`
	Type   string `json:"type"` // Ethernet type (e.g., IPv4, ARP, etc.)
}

type Layer3 struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Protocol string `json:"protocol"`
	TTL      uint8  `json:"ttl"`
}

type Layer4 struct {
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Seq      uint32 `json:"seq,omitempty"` // Seq and Ack are TCP-specific
	Ack      uint32 `json:"ack,omitempty"`
	Flags    string `json:"flags,omitempty"` // TCP flags, omit if empty for UDP
	Protocol string `json:"protocol"`        // "TCP" or "UDP"
}

type PacketData struct {
	Timestamp string `json:"timestamp"`
	Length    int    `json:"length"`
	Layer2    Layer2 `json:"layer_2"`
	Layer3    Layer3 `json:"layer_3"`
	Layer4    Layer4 `json:"layer_4"`
	Payload   []byte `json:"payload"`
}

const (
	queueSize = 1000 // Adjust as needed
)

var (
	device      = flag.String("device", "", "Network interface name (e.g., eth0)")
	destination = flag.String("destination", "", "Logstash server and port (e.g., localhost:5044)")
)

func usage() {
	fmt.Printf("Usage: %s [options]\n", os.Args[0])
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	snapshotLen := int32(1024)
	timeout := pcap.BlockForever

	if *device == "" {
		fmt.Println("Error: no network device specified!")
		flag.Usage()
		os.Exit(1)
	}

	if *destination == "" {
		fmt.Println("Error: no server destination specified!")
		flag.Usage()
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(*device, snapshotLen, true, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Establish a TCP connection to Logstash
	conn, err := net.Dial("tcp", *destination)
	if err != nil {
		log.Fatalf("Failed to connect to Logstash: %v", err)
	}
	log.Printf("Connected to logstash server on %s", *destination)
	defer conn.Close()

	// Create a buffered channel for packet data
	packetQueue := make(chan PacketData, queueSize)
	var wg sync.WaitGroup

	// Start a goroutine for processing and sending packets
	wg.Add(1)
	go func() {
		defer wg.Done()
		for data := range packetQueue {
			jsonData, err := json.Marshal(data)
			if err != nil {
				log.Printf("Error marshaling data: %v", err)
				continue
			}

			_, err = conn.Write(append(jsonData, '\n')) // Send the JSON data followed by a newline
			if err != nil {
				log.Printf("Error sending data to Logstash: %v", err)
			}
		}
	}()

	log.Printf("Started listening to traffic on interface %s", *device)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet, packetQueue)
	}

	// Close the queue and wait for processing to finish
	close(packetQueue)
	wg.Wait()
}

func processPacket(packet gopacket.Packet, packetQueue chan PacketData) {
	var layer2 Layer2
	var layer3 Layer3
	var layer4 Layer4

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		eth, _ := ethernetLayer.(*layers.Ethernet)
		layer2 = Layer2{
			SrcMAC: eth.SrcMAC.String(),
			DstMAC: eth.DstMAC.String(),
			Type:   eth.EthernetType.String(),
		}
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		layer3 = Layer3{
			SrcIP:    ip.SrcIP.String(),
			DstIP:    ip.DstIP.String(),
			Protocol: ip.Protocol.String(),
			TTL:      ip.TTL,
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		layer4 = Layer4{
			SrcPort:  uint16(tcp.SrcPort),
			DstPort:  uint16(tcp.DstPort),
			Seq:      tcp.Seq,
			Ack:      tcp.Ack,
			Flags:    tcpFlagsToString(tcp),
			Protocol: "TCP",
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		layer4 = Layer4{
			SrcPort:  uint16(udp.SrcPort),
			DstPort:  uint16(udp.DstPort),
			Protocol: "UDP",
		}
	}

	var payload []byte
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload = appLayer.Payload()
	}

	// Construct the PacketData structure
	data := PacketData{
		Timestamp: time.Now().Format(time.RFC3339),
		Length:    len(packet.Data()),
		Layer2:    layer2,
		Layer3:    layer3,
		Layer4:    layer4,
		Payload:   payload,
	}

	// Send packet data to the queue
	packetQueue <- data

}

func tcpFlagsToString(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "SYN "
	}
	if tcp.ACK {
		flags += "ACK "
	}
	if tcp.FIN {
		flags += "FIN "
	}
	if tcp.RST {
		flags += "RST "
	}
	if tcp.PSH {
		flags += "PSH "
	}
	if tcp.URG {
		flags += "URG "
	}
	return flags
}
