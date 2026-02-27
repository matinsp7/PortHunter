package utils

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ParsePortRange(r string) (int, int) {
	parts := strings.Split(r, "-")
	start, _ := strconv.Atoi(parts[0])
	end := start
	if len(parts) > 1 {
		end, _ = strconv.Atoi(parts[1])
	}
	return start, end
}

func ResolveTarget(target string) (net.IP, error) {
	ip := net.ParseIP(target)
	if ip != nil {
		return ip, nil
	}

	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("cannot resolve target")
	}

	return ips[0].To4(), nil
}

func GetActiveInterface() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	for _, device := range devices {
		if len(device.Addresses) > 0 {
			return device.Name, nil
		}
	}
	return "", fmt.Errorf("no active network interface found")
}

func GetInterfaceInfo(device string) (net.IP, net.HardwareAddr, *net.IPNet) {

	iface, _ := net.InterfaceByName(device)
	addrs, _ := iface.Addrs()

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP, iface.HardwareAddr, ipnet
		}
	}
	log.Fatal("No IPv4 found")
	return nil, nil, nil
}

func InSubnet(ip net.IP, subnet *net.IPNet) bool {
	return subnet.Contains(ip)
}

func GetDefaultGateway(device string) net.IP {

	file, err := os.Open("/proc/net/route")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header

	for scanner.Scan() {

		fields := strings.Fields(scanner.Text())

		if len(fields) < 3 {
			continue
		}

		iface := fields[0]
		destination := fields[1]
		gatewayHex := fields[2]

		if destination == "00000000" && iface == device {

			gatewayBytes, err := hex.DecodeString(gatewayHex)
			if err != nil {
				log.Fatal(err)
			}

			// little endian
			ip := net.IP{
				gatewayBytes[3],
				gatewayBytes[2],
				gatewayBytes[1],
				gatewayBytes[0],
			}

			return ip
		}
	}

	log.Fatal("Default gateway not found")
	return nil
}

func ResolveARP(handle *pcap.Handle,
	srcIP net.IP,
	srcMAC net.HardwareAddr,
	targetIP net.IP) net.HardwareAddr {

	fmt.Println("Resolving MAC for:", targetIP)

	handle.SetBPFFilter("arp")

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err := gopacket.SerializeLayers(buffer, opts, eth, arp)
	if err != nil {
		log.Fatal("ARP serialize error:", err)
	}

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal("ARP send error:", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	timeout := time.After(3 * time.Second)

	for {
		select {

		case packet := <-packetSource.Packets():

			if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {

				arpReply := arpLayer.(*layers.ARP)

				if arpReply.Operation == layers.ARPReply &&
					net.IP(arpReply.SourceProtAddress).Equal(targetIP) {

					mac := net.HardwareAddr(arpReply.SourceHwAddress)

					fmt.Println("Resolved MAC:", mac)

					return mac
				}
			}

		case <-timeout:
			log.Fatal("ARP resolution timeout")
		}
	}
}