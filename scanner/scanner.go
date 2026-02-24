package scanner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type ScanType string

const (
	TCPConnect ScanType = "connect"
	TCPSYN     ScanType = "syn"
	TCPFIN     ScanType = "fin"
	TCPNULL    ScanType = "null"
	TCPXMAS    ScanType = "xmas"
	TCPSYNACK  ScanType = "synack"
	UDPScan    ScanType = "udp"
)

type Scanner struct {
	Target     string
	StartPort  int
	EndPort    int
	Timeout    time.Duration
	Workers    int
	ScanType   ScanType
	SourcePort uint16
}

func (s *Scanner) Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nScan interrupted.")
		cancel()
	}()

	ports := make(chan int, s.Workers)
	var wg sync.WaitGroup

	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range ports {
				select {
				case <-ctx.Done():
					return
				default:
					s.scanPort(port)
				}
			}
		}()
	}

	for p := s.StartPort; p <= s.EndPort; p++ {
		ports <- p
	}
	close(ports)
	wg.Wait()
}

func (s *Scanner) scanPort(port int) {

}
