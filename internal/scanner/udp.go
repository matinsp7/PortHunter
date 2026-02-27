package scanner

import (
	"fmt"
	"net"
	"time"
	"github.com/matinsp7/PortScanner/internal/model"
)

func udpScan(scanner *model.Scanner, port int) {
	
	address := fmt.Sprintf("%s:%d", scanner.Target , port)

	
	conn, err := net.DialTimeout("udp", address, scanner.Timeout)
	if err != nil {
		fmt.Printf("UDP %d: closed (dial error)\n", port)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(scanner.Timeout))

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
			scanner.Mutex.Lock()
			scanner.Result[port]=model.Filtered
			scanner.Mutex.Unlock()
			return
		}
        
		scanner.Mutex.Lock()
		scanner.Result[port] = model.Closed
		scanner.Mutex.Unlock()
		return
	}
     
	 scanner.Mutex.Lock()
	 scanner.Result[port]= model.Open
	 scanner.Mutex.Unlock()
}