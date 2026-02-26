package tcpsp

import (
	"fmt"
	"log"
	"math/rand/v2"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/matinsp7/PortScanner/model"
	"github.com/matinsp7/PortScanner/utils"
)

func TCPSynConnect(scanner *model.Scanner) {
	iface, err := utils.GetActiveInterface()
	if err != nil {
		log.Println(err)
		return
	}

	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Println(err)
		return
	}
	scanner.Handle = handle
	defer scanner.Handle.Close()

	srcIP, srcMAC, subnet := utils.GetInterfaceInfo(iface)

	var nextHop net.IP
	if utils.InSubnet(scanner.Target, subnet) {
		nextHop = scanner.Target
		fmt.Println("Target is inside subnet")
	} else {
		nextHop = utils.GetDefaultGateway(iface)
		fmt.Println("Target outside subnet → using gateway:", nextHop)
	}

	scanner.DstMAC = utils.ResolveARP(scanner.Handle, srcIP, srcMAC, nextHop)

	filter := fmt.Sprintf("tcp and host %s or icmp", scanner.Target)
	scanner.Handle.SetBPFFilter(filter)

	go listen(scanner)

	utils.RunWorkers(scanner, sendSYN)

}

func listen(scanner *model.Scanner) {

	fmt.Println("packet:")


	ps := gopacket.NewPacketSource(scanner.Handle, scanner.Handle.LinkType())

	for packet := range ps.Packets() {

		fmt.Println("packet:", packet)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			tcp := tcpLayer.(*layers.TCP)

			scanner.Mutex.Lock()

			if tcp.SYN && tcp.ACK {
				scanner.Result[int(tcp.SrcPort)] = model.Open
				sendRST(scanner, tcp)
			} else if tcp.RST {
				scanner.Result[int(tcp.SrcPort)] = model.Closed
			}

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

func sendPacket(scanner *model.Scanner, layersToSend ...gopacket.SerializableLayer) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buffer, opts, layersToSend...)
	scanner.Handle.WritePacketData(buffer.Bytes())
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