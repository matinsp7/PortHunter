package scanner

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
   
	"github.com/matinsp7/PortScanner/tcpsp"
	"github.com/matinsp7/PortScanner/udp"
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
	if err := s.scanvalidation(); err != nil {
         fmt.Println(err)
		 return
   }
   fmt.Println("Starting scan...")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nScan interrupted.")
		cancel()
		os.Exit(1)
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
	fmt.Println("Scan completed.")
}

func (s *Scanner) scanPort(port int) {
	switch s.ScanType {
	case TCPConnect:
		tcpsp.TcpConnectScan(s.Target, port, s.Timeout)
	case UDPScan:
		udp.UdpScan(s.Target, port, s.Timeout)
	}
} 

func (s *Scanner)scanvalidation() error {
	if s.StartPort < 1 || s.StartPort > 65535 {
		return fmt.Errorf("Invalid start port")
	} else if s.EndPort < 1 || s.EndPort > 65535 || s.EndPort < s.StartPort {
		return fmt.Errorf("Invalid end port")
	} else if s.Timeout < 1 || s.Timeout > 100*time.Second {
		return fmt.Errorf("timeout is not correct")
	} else if s.Workers < 1 || s.Workers > 1000 {
		return fmt.Errorf("count of workers is not true.")
	}
	return nil
}
