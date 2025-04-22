# Network Monitoring System

A powerful cross-platform network monitoring system for real-time device detection, fingerprinting, and security analysis. This tool provides advanced features to monitor network activity, detect threats, and identify unauthorized devices on your network.

## Features

- **Real-time device detection**: Discover and track all devices on your network
- **Device fingerprinting**: Identify device types, operating systems, and capabilities
- **Threat detection**:
  - DHCP spoofing detection
  - ARP poisoning detection
  - DNS spoofing detection
  - Port scanning detection
  - Unauthorized device alerts
- **Vulnerability assessment**: Analyze open ports and services for potential security risks
- **Network change monitoring**: Track changes in your network over time
- **Cross-platform support**: Works on Linux, Windows, and macOS
- **Terminal-based interface**: Clean, colorful, and easy-to-use console output
- **Security restrictions**: Limits tool usage to authorized machines only

## Requirements

- Python 3.7 or higher
- Nmap (For full functionality)
- Superuser/Administrator privileges (for some features)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/Abdouyami/network-monitor.git
   cd network-monitor
   ```

2. Run the setup script to install all dependencies:
   ```
   python setup.py
   ```

### Dependencies

The setup script will install the following Python packages:
- `python-nmap`: For network scanning
- `scapy`: For packet capture and analysis
- `netifaces`: For network interface information
- `mac-vendor-lookup`: For identifying device vendors
- `zeroconf`: For mDNS device discovery
- `colorama`: For colorful terminal output

## Usage

### Basic Scan

To perform a basic network scan:
```
python network_monitor.py
```

### Continuous Monitoring

To start continuous monitoring of your network:
```
python network_monitor.py --monitor
```

### Threat Detection

To run a focused threat detection scan:
```
python network_monitor.py --threat-scan
```

### Vulnerability Assessment

To perform a vulnerability assessment:
```
python network_monitor.py --vuln-scan
```

### Comprehensive Full Scan

To run a comprehensive scan that combines all detection features:
```
python network_monitor.py --full-scan
```

This will run all 8 scan types sequentially:
1. Device discovery
2. DHCP server detection
3. ARP spoofing detection
4. DNS spoofing detection
5. Device fingerprinting
6. Port scanning detection
7. Vulnerability scanning
8. Threat analysis

### Command Line Options

```
usage: network_monitor.py [-h] [-n NETWORK] [-o OUTPUT] [-i INTERVAL] [-v] 
                          [--monitor] [--quick-scan] [--threat-scan] [--vuln-scan]
                          [--full-scan] [--add-to-whitelist ADDRESS] [--show-whitelist]
                          [--show-device IP] [--dhcp-detect] [--arp-detect]
                          [--dns-detect] [--port-scan-detect] [--no-color] [--json]

Enhanced Network Monitoring and Threat Detection

options:
  -h, --help            show this help message and exit
  -n NETWORK, --network NETWORK
                        Network range to scan (CIDR notation)
  -o OUTPUT, --output OUTPUT
                        Output directory for results
  -i INTERVAL, --interval INTERVAL
                        Scan interval in seconds
  -v, --verbose         Enable verbose output

Scan Modes:
  --monitor             Run continuous monitoring
  --quick-scan          Perform a quick scan and exit
  --threat-scan         Focus on threat detection
  --vuln-scan           Perform vulnerability scanning
  --full-scan           Run a comprehensive scan with all detection features

Management:
  --add-to-whitelist ADDRESS
                        Add IP or MAC to whitelist
  --show-whitelist      Show current whitelist
  --show-device IP      Show detailed info for a specific device
  --config-setup        Set up security configuration for authorized access

Threat Detection:
  --dhcp-detect         Detect DHCP servers
  --arp-detect          Detect ARP spoofing
  --dns-detect          Detect DNS spoofing
  --port-scan-detect    Detect port scanning activity

Output Options:
  --no-color            Disable colored output
  --json                Output in JSON format where applicable
```

## Examples

### Monitor a specific network range
```
python network_monitor.py --network 192.168.1.0/24 --monitor
```

### Detect DHCP servers on the network
```
python network_monitor.py --dhcp-detect
```

### Add a device to the whitelist
```
python network_monitor.py --add-to-whitelist 192.168.1.100
```
or
```
python network_monitor.py --add-to-whitelist 00:11:22:33:44:55
```

### Show detailed information about a specific device
```
python network_monitor.py --show-device 192.168.1.100
```

### Run a comprehensive scan with all detection features
```
python network_monitor.py --full-scan
```

### Set up security configuration (restrict tool access)
```
python network_monitor.py --config-setup
```

## Architecture

The system is built with a modular architecture:

- **Scanner**: Responsible for network scanning and device discovery using nmap
- **Fingerprinter**: Handles device identification and OS detection
- **Detector**: Implements various threat detection techniques
- **Models**: Data structures for devices, scan results, and threats
- **Helpers**: Utility functions for data handling and analysis

## Security Features

### Access Control
The tool includes a security configuration system that restricts usage to authorized machines only:
- **IP verification**: Validates that the tool is running from an authorized IP address
- **MAC verification**: Checks that the machine's MAC address matches the authorized configuration
- **Optional token authentication**: Adds an extra layer of security through a password-like token

### Configuration
Run `python network_monitor.py --config-setup` to configure security settings. You'll be prompted to:
- Enter an authorized IP address (defaults to current IP)
- Enter an authorized MAC address (defaults to current MAC)
- Enable/disable token authentication
- Set a secret token (if token authentication is enabled)
- Specify an authorized port (optional)

After configuration, the tool will validate credentials before allowing any scans. If validation fails, you'll see an `[ACCESS DENIED]` message.

To run the tool on a specific port (when port restriction is enabled):
```bash
python network_monitor.py --port 8080 --quick-scan
```

## Security Notice

This tool is designed for legitimate network monitoring and security assessment. Please use responsibly and only on networks you own or have permission to scan. Unauthorized network scanning may be illegal in some jurisdictions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## Meet the Team

<div align="center">
  <table>
    <tr>
      <td align="center">
        <img src="https://github.com/Abdouyami.png" width="100px;" alt="BELHAMICI ABDERRAHMANE" style="border-radius:50%"/><br />
        <b>BELHAMICI ABDERRAHMANE</b><br />
        <div>
          <a href="https://github.com/Abdouyami"><img src="https://img.shields.io/badge/GitHub-%23181717.svg?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/></a>
          <a href="https://www.linkedin.com/in/abderrahmane-belhamici-6a8628288/"><img src="https://img.shields.io/badge/LinkedIn-%230A66C2.svg?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"/></a>
          <a href="mailto:belhamiciabderrahmane@gmail.com"><img src="https://img.shields.io/badge/Email-%23EA4335.svg?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"/></a>
        </div>
        <p><i>Network Security Specialist/AI Engineer</i></p>
      </td>
      <td align="center">
        <img src="https://github.com/Madjid01.png" width="100px;" alt="BOUKHALFA LYES" style="border-radius:50%"/><br />
        <b>BOUKHALFA LYES</b><br />
        <div>
          <a href="https://github.com/Madjid01"><img src="https://img.shields.io/badge/GitHub-%23181717.svg?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"/></a>
          <a href="https://www.linkedin.com/in/lyes-boukhalfa-642780340/"><img src="https://img.shields.io/badge/LinkedIn-%230A66C2.svg?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"/></a>
          <a href="mailto:lyesboukhalfa18@gmail.com"><img src="https://img.shields.io/badge/Email-%23EA4335.svg?style=for-the-badge&logo=gmail&logoColor=white" alt="Email"/></a>
        </div>
        <p><i>Network Security Specialist/Software Engineer</i></p>
      </td>
    </tr>
  </table>
</div>

<div align="center">
  <p><b>🔒 Network Monitoring System Creators 🔒</b></p>
  <p><i>Passionate about network security and technology innovation</i></p>
</div>

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

- Nmap: For the powerful network scanning capabilities
- Scapy: For packet manipulation and analysis
- The open-source community: For the amazing libraries that make this tool possible