package utils

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/matinsp7/PortScanner/internal/model"
)

func RunWorkers(scanner *model.Scanner, scanPort func(*model.Scanner, int)) {
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