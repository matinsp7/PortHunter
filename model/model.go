package model

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
)

type ScanType string

const (
	TCPConnect ScanType = "connect"
	TCPSYN     ScanType = "syn"
	UDPScan    ScanType = "udp"
)

type PortState int

const (
	Unknown PortState = iota
	Open
	Closed
	Filtered
)

type Scanner struct {
	SrcIP      net.IP
	SourcePort int
	SrcMAC     net.HardwareAddr
	DstMAC     net.HardwareAddr
	Target     net.IP
	StartPort  int
	EndPort    int
	ScanType   ScanType
	Handle     *pcap.Handle
	Timeout    time.Duration
	Workers    int
	Mutex      sync.Mutex
	Result     map[int]PortState
}
