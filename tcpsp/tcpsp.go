package tcpsp

import (
	"fmt"
	"net"
	"time"
)

func TcpConnectScan(target string, port int, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err == nil {
		fmt.Printf("[OPEN] TCP %d\n", port)
		conn.Close()
	}
}
