package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/matinsp7/PortScanner/model"
	"github.com/matinsp7/PortScanner/scanner"
	"github.com/matinsp7/PortScanner/utils"
)

func main() {
	target := flag.String("target", "", "Target IP address")
	portRange := flag.String("ports", "1-1024", "Port range (e.g., 1-1000)")
	scanType := flag.String("scan", "connect", "Scan type: connect, syn, fin, null, xmas, synack, udp")
	timeout := flag.Int("timeout", 3, "Timeout in seconds")
	workers := flag.Int("workers", 200, "Number of concurrent workers")
	sourcePort := flag.Int("sport", 0, "Custom source port (optional)")

	flag.Parse()

	if *target == "" {
		log.Fatal("Target IP is required")
	}

	startPort, endPort := utils.ParsePortRange(*portRange)

	scannerModel := &model.Scanner{
		SourcePort: *sourcePort,
		Target:     *target,
		StartPort:  startPort,
		EndPort:    endPort,
		ScanType:   model.ScanType(*scanType),
		Timeout:    time.Duration(*timeout) * time.Second,
		Workers:    *workers,
	}

	ctx := context.Background()

	scanner.Run(ctx, scannerModel)
}
