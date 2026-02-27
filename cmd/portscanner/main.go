package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/matinsp7/PortScanner/internal/model"
	"github.com/matinsp7/PortScanner/internal/scanner"
	"github.com/matinsp7/PortScanner/internal/utils"
)

func main() {
	target := flag.String("target", "", "Target IP address")
	portRange := flag.String("ports", "1-1024", "Port range (e.g., 1-1000)")
	scanType := flag.String("scan", "connect", "Scan type: connect, syn, udp")
	timeout := flag.Int("timeout", 3, "Timeout in seconds [1-60]")
	workers := flag.Int("workers", 200, "Number of concurrent workers [1-1000]")

	flag.Parse()

	if *target == "" {
		log.Fatal("Target IP is required")
	}

	ip, err := utils.ResolveTarget(*target)
	if err != nil {
		log.Fatal(err)
	}

	startPort, endPort := utils.ParsePortRange(*portRange)

	scannerModel := &model.Scanner{
		Target:     ip,
		StartPort:  startPort,
		EndPort:    endPort,
		ScanType:   model.ScanType(*scanType),
		Timeout:    time.Duration(*timeout) * time.Second,
		Workers:    *workers,
		Result: make(map[int]model.PortState),
	}

	ctx := context.Background()

	scanner.Run(ctx, scannerModel)
}