package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/matinsp7/PortScanner/model"
	"github.com/matinsp7/PortScanner/tcpsp"
	"github.com/matinsp7/PortScanner/utils"
)

func Run(ctx context.Context, scanner *model.Scanner) {
	if err := scanvalidation(scanner); err != nil {
		fmt.Println(err)
		return
	}

	switch scanner.ScanType {
	case model.TCPConnect:
		utils.RunWorkers(scanner, tcpsp.TcpConnectScan)
		// tcpsp.TcpConnectScan(scanner.Target, port, scanner.Timeout)
	case model.TCPSYN:
		tcpsp.TCPSynConnect(scanner)
	case model.UDPScan:
		// udp.UdpScan(scanner.Target, port, scanner.Timeout)
	}

	// printResults()
}

// func scanPort(scanner *model.Scanner, port int) {
// 	switch scanner.ScanType {
// 	case model.TCPConnect:
// 		tcpsp.TcpConnectScan(scanner.Target, port, scanner.Timeout)
// 	case model.TCPSYN:
// 		tcpsp.TCPSynConnect(scanner)
// 	case model.UDPScan:
// 		udp.UdpScan(scanner.Target, port, scanner.Timeout)
// 	}
// }

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

