# Combined Network Scanner Tool

![Kali Linux Compatible](https://img.shields.io/badge/Kali_Linux-Compatible-brightgreen)

> **Important Note**: This tool is specifically designed to work on **Kali Linux** as it relies on security tools that come pre-installed with Kali. While it might work on other Linux distributions, full functionality is only guaranteed on Kali Linux.

## Features

### External Scanning
- **Nmap Scan**: Discovers open ports and services
- **Nuclei Scan**: Detects web vulnerabilities
- **Nikto Scan**: Web server vulnerability scanner
- **Amass Scan**: Subdomain enumeration tool

### Internal Scanning
- **Nmap Host Discovery**: Finds active hosts on the network
- **SMBmap**: Scans SMB shares and permissions
- **Enum4linux**: Enumerates Windows/Samba information
- **Sniper**: Automated scanning tool
- **CrackMapExec**: SMB/Samba network testing tool
- **Sparta**: Integrated scanning environment

## Requirements

### Supported Operating System
- **Kali Linux** (recommended)
- Other Debian-based Linux distributions may work but aren't officially supported

### Kali Linux Tools Required
These tools come pre-installed with Kali Linux: nmap nuclei nikto amass smbmap enum4linux sniper crackmapexec sparta

### Python Dependencies
- Python 3.x
- tkinter (usually included with Python)

## Kali Linux then script instalattion

1. First, update your Kali Linux:
   ```bash
   sudo apt update && sudo apt upgrade -y

   git clone https://github.com/mihal3w/Combined-Network-Scanner-Tool.git
    cd Combined-Network-Scanner-Tool
    sudo python3 Combined-Network-Scanner-Tool
