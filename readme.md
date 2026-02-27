# PortHunter

A fast and concurrent port scanner written in Go.
It allows you to scan a target IP address and discover open ports along with their associated services.

## Features

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

Prerequisites

* Go 1.20+
* make
* Root privileges (required for SYN and UDP scans)

Verify installation:

```bash
go version
make --version
```

Clone the repository:

```bash
git clone https://github.com/matinsp7/PortHunter.git.git
cd PortHunter
```

Install Globally:

```bash
make install
```

---

## ⚙️ Usage

After installation, you can run:

```bash
porthunter -target <IP> [options]
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

## Example

### TCP Connect Scan

```bash
porthunter -target 192.168.1.1
```

### SYN Scan

```bash
sudo porthunter -target 192.168.1.1 -scan syn
```

### UDP Scan on Custom Ports

```bash
sudo porthunter -target 192.168.1.1 -scan udp -ports 20-200
```

> ⚠️ SYN and UDP scans usually require root privileges.

---

## Supported Scan Types

| Scan Type | Description                           |
| --------- | ------------------------------------- |
| connect   | Full TCP connection (3-way handshake) |
| syn       | Half-open SYN scan                    |
| udp       | UDP port scan                         |

---

## Uninstall

```bash
make uninstall
```

---
## Disclaimer

This tool is intended for educational purposes and authorized security testing only.
Do not scan systems without proper permission.

---

## 📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

---