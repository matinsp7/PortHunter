package model

import "time"

type ScanType string

const (
	TCPConnect ScanType = "connect"
	TCPSYN     ScanType = "syn"
	UDPScan    ScanType = "udp"
)

type Scanner struct {
	SourcePort int
	Target     string
	StartPort  int
	EndPort    int
	ScanType   ScanType
	Timeout    time.Duration
	Workers    int
}
