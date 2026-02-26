package tcpsp

import (
	"fmt"
	"net"

	"github.com/matinsp7/PortScanner/model"
)

func TcpConnectScan(scanner *model.Scanner, port int) {
	address := fmt.Sprintf("%s:%d", scanner.Target, port)
	conn, err := net.DialTimeout("tcp", address, scanner.Timeout)
	if err == nil {
		// fmt.Printf("[OPEN] TCP %d\n", port)
		scanner.Mutex.Lock()
		scanner.Result[port] = model.Open
		scanner.Mutex.Unlock()
		conn.Close()
	}
}
