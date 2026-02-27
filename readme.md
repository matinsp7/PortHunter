# 🚀 PortHunter

A fast and concurrent port scanner written in Go.
It allows you to scan a target IP address and discover open ports along with their associated services.

## ✨ Features

* TCP Connect Scan
* TCP SYN Scan (Half-Open Scan)
* UDP Scan
* Custom port range selection
* Custom timeout configuration
* Configurable number of concurrent workers
* Basic service detection for common ports (HTTP, HTTPS, SSH, FTP, etc.)
* Built using raw packet handling with `gopacket` and `pcap`

---

## 🛠️ Installation

Make sure you have Go installed:

```bash
go version
```

Clone the repository:

```bash
git clone https://github.com/matinsp7/PortScanner.git
cd PortHunter
```

Install dependencies:

```bash
go mod tidy
```

---

## ⚙️ Usage

```bash
go run main.go -target <IP> [options]
```

### Required Argument

| Flag      | Description                   |
| --------- | ----------------------------- |
| `-target` | Target IP address or hostname |

### Optional Arguments

| Flag       | Default | Description                        |
| ---------- | ------- | ---------------------------------- |
| `-ports`   | 1-1024  | Port range (e.g., 1-65535)         |
| `-scan`    | connect | Scan type: `connect`, `syn`, `udp` |
| `-timeout` | 3       | Timeout in seconds                 |
| `-workers` | 200     | Number of concurrent workers       |

---

## 📌 Example

### TCP Connect Scan

```bash
go run main.go -target 192.168.1.1
```

### SYN Scan

```bash
sudo go run main.go -target 192.168.1.1 -scan syn
```

### UDP Scan on Custom Ports

```bash
sudo go run main.go -target 192.168.1.1 -scan udp -ports 20-200
```

> ⚠️ SYN and UDP scans usually require root privileges.

---

## 🔎 Supported Scan Types

| Scan Type | Description                           |
| --------- | ------------------------------------- |
| connect   | Full TCP connection (3-way handshake) |
| syn       | Half-open SYN scan                    |
| udp       | UDP port scan                         |

---

## 🌐 Detected Common Services

The scanner maps common ports to known services:

* 21 → FTP
* 22 → SSH
* 23 → Telnet
* 25 → SMTP
* 53 → DNS
* 80 → HTTP
* 123 → NTP
* 143 → IMAP
* 443 → HTTPS

---

## ⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.
Do not scan systems without proper permission.

---

## 📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

---