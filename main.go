package main

import (
	"flag"
	"log"
	"time"

	"github.com/matinsp7/PortScanner/scanner"
	"github.com/matinsp7/PortScanner/utils"
)

func main() {
	target := flag.String("target", "", "Target IP address")
	portRange := flag.String("ports", "1-1024", "Port range (e.g., 1-1000)")
	scanType := flag.String("scan", "connect", "Scan type: connect, syn, fin, null, xmas, synack, udp")
	timeout := flag.Int("timeout", 2, "Timeout in seconds")
	workers := flag.Int("workers", 100, "Number of concurrent workers")
	sourcePort := flag.Int("sport", 0, "Custom source port (optional)")

	flag.Parse()

	if *target == "" {
		log.Fatal("Target IP is required")
	}

	startPort, endPort := utils.ParsePortRange(*portRange)

	scanner := &scanner.Scanner{
		Target:     *target,
		StartPort:  startPort,
		EndPort:    endPort,
		Timeout:    time.Duration(*timeout) * time.Second,
		Workers:    *workers,
		ScanType:   scanner.ScanType(*scanType),
		SourcePort: uint16(*sourcePort),
	}

	scanner.Run()
}
