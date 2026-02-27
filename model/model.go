package model

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ScanType string

const (
	TCPConnect ScanType = "connect"
	TCPSYN     ScanType = "syn"
	UDPScan    ScanType = "udp"
)

var Port_service = map[int]string {
	21 : "FTP" ,
	22:  "SSH",
	23:    "Telnet",
	25:    "SMTP",
    53 : "DNS" ,
	80 : "HTTP" ,
	123 : "NTP" ,
	143:   "IMAP",
	443 : "HTTPS" ,
}

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
	PortMap    map[layers.TCPPort]int
	Result     map[int]PortState
}
