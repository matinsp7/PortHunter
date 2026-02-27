package scanner

import (
	"fmt"
	"log"
	"math/rand"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/matinsp7/PortScanner/internal/model"
	"github.com/matinsp7/PortScanner/internal/utils"
)

func tcpSynConnect(scanner *model.Scanner) {

	device, err := utils.GetActiveInterface()
	if err != nil {
		log.Fatal(err)
	}

	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	scanner.Handle = handle
	defer scanner.Handle.Close()

	srcIP, srcMAC, subnet := utils.GetInterfaceInfo(device)

	var nextHop net.IP
	if utils.InSubnet(scanner.Target, subnet) {
		nextHop = scanner.Target
		fmt.Println("Target is inside subnet")
	} else {
		nextHop = utils.GetDefaultGateway(device)
		fmt.Println("Target outside subnet → using gateway:", nextHop)
	}

	dstMAC := utils.ResolveARP(scanner.Handle, srcIP, srcMAC, nextHop)

	scanner.SrcIP = srcIP
	scanner.SrcMAC = srcMAC
	scanner.DstMAC = dstMAC
	scanner.PortMap = make(map[layers.TCPPort]int)

	filter := fmt.Sprintf("tcp and host %s or icmp", scanner.Target)
	scanner.Handle.SetBPFFilter(filter)
	go listen(scanner)
	runWorkers(scanner, sendSYN)

}

func listen(scanner *model.Scanner) {

	ps := gopacket.NewPacketSource(scanner.Handle, scanner.Handle.LinkType())

	for packet := range ps.Packets() {

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			tcp := tcpLayer.(*layers.TCP)

			scanner.Mutex.Lock()

			originalPort, exists := scanner.PortMap[tcp.DstPort]
			if !exists {
				scanner.Mutex.Unlock()
				continue
			}

			if tcp.SYN && tcp.ACK {
				scanner.Result[originalPort] = model.Open
				sendRST(scanner, tcp)
			} else if tcp.RST {
				scanner.Result[originalPort] = model.Closed
			}

			scanner.Mutex.Unlock()
		}

		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			scanner.Mutex.Lock()
			scanner.Result[int(scanner.StartPort)] = model.Filtered
			scanner.Mutex.Unlock()
		}
	}
}

func sendSYN(scanner *model.Scanner, port int) {
	eth := &layers.Ethernet{
		SrcMAC:       scanner.SrcMAC,
		DstMAC:       scanner.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    scanner.SrcIP,
		DstIP:    scanner.Target,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	srcPort := layers.TCPPort(40000 + port)
	scanner.Mutex.Lock()
	scanner.PortMap[srcPort] = port
	scanner.Mutex.Unlock()

	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: layers.TCPPort(port),
		SYN:     true,
		Seq:     rand.Uint32(),
		Window:  14600,
	}

	tcp.SetNetworkLayerForChecksum(ip)

	sendPacket(scanner, eth, ip, tcp)
}

func sendRST(scanner *model.Scanner, received *layers.TCP) {

	eth := &layers.Ethernet{
		SrcMAC:       scanner.SrcMAC,
		DstMAC:       scanner.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		SrcIP:    scanner.SrcIP,
		DstIP:    scanner.Target,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: received.DstPort,
		DstPort: received.SrcPort,
		RST:     true,
		Seq:     received.Ack,
	}

	tcp.SetNetworkLayerForChecksum(ip)

	sendPacket(scanner, eth, ip, tcp)
}

func sendPacket(scanner *model.Scanner, layersToSend ...gopacket.SerializableLayer) {

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buffer, opts, layersToSend...)
	scanner.Handle.WritePacketData(buffer.Bytes())
}