package udp

import (
	"fmt"
	"net"
	"time"
)

func UdpScan(target string, port int, timeout time.Duration) {
	
	address := fmt.Sprintf("%s:%d", target, port)

	

	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		fmt.Printf("UDP %d: closed (dial error)\n", port)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	var payload []byte 

	if port == 53 {
		payload = []byte{
		0x01, 0x00, 
		0x00, 0x01, 
		0x00, 0x00, 
		0x00, 0x00, 
		0x00, 0x00, 
		0x07, 'a' , 'p' , 'a' , 'r' , 'a' , 't',
		0x03, 'c','o','m',
		0x00,
		0x00, 0x01, 
		0x00, 0x01,}
	} else {
		payload = []byte{0x00}
	}

	_ , err = conn.Write(payload)
	if err != nil {
		fmt.Printf("UDP %d: closed (write error)\n", port)
		return
	}

	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)

	if err != nil {
		netErr, ok := err.(net.Error)
		if ok && netErr.Timeout() {
			fmt.Printf("UDP %d: open|filter\n", port)
			return
		}

		fmt.Printf("[close] UDP %d \n", port)
		return
	}

	fmt.Printf("[open] UDP %d \n", port)
}