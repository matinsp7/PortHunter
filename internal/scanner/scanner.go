package scanner

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/matinsp7/PortScanner/model"
)

func Run(ctx context.Context, scanner *model.Scanner) {
	if err := scanvalidation(scanner); err != nil {
		fmt.Println(err)
		return
	}

	switch scanner.ScanType {
	case model.TCPConnect:
		runWorkers(scanner, tcpConnectScan)
	case model.TCPSYN:
		tcpSynConnect(scanner)
	case model.UDPScan:
		runWorkers(scanner, udpScan)
	}
}

func scanvalidation(scanner *model.Scanner) error {
	if scanner.StartPort < 1 || scanner.EndPort > 65535 {
		return fmt.Errorf("Invalid start port")
	} else if scanner.EndPort < 1 || scanner.EndPort > 65535 || scanner.EndPort < scanner.StartPort {
		return fmt.Errorf("Invalid end port")
	} else if scanner.Timeout < 1 || scanner.Timeout > 100*time.Second {
		return fmt.Errorf("timeout is not correct")
	} else if scanner.Workers < 1 || scanner.Workers > 1000 {
		return fmt.Errorf("count of workers is not true.")
	}
	return nil
}

func runWorkers(scanner *model.Scanner, scanPort func(*model.Scanner, int)) {
	fmt.Println("Starting scan...")

	ports := make(chan int, scanner.Workers)
	var wg sync.WaitGroup

	for i := 0; i < scanner.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				scanPort(scanner, port)
				time.Sleep(scanner.Timeout)
			}
		}()
	}

	for p := scanner.StartPort; p <= scanner.EndPort; p++ {
		ports <- p
	}
	close(ports)
	wg.Wait()
	printResults(scanner)
	fmt.Println("Scan completed.")
	os.Exit(0)
}

func printResults(scanner *model.Scanner) {
	for port, state := range scanner.Result {
		if state == model.Open {
			fmt.Println("[OPEN] Port", port, ":", model.Port_service[port])
		}
	}
}
